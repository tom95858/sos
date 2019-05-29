/*
 * The DSOS request layer sends messages to one or more servers and
 * matches them up with response messages that later arrive.  It is used
 * by the RPC layer. A message is a 2k-byte buffer of formatted data
 * represented as a large union of C structures in dsos/server/dsos_msg_layout.h.
 * The RPC parameters are marshalled in and out of these messages.
 *
 * To send a message to a single server, a request is first allocated:
 *
 *   dsos_req_t *req = dsos_req_new(callback_fn, ctxt);
 *
 * By requiring allocation, this layer can support transports that
 * directly provide their buffers, thereby avoiding a copy. Then the
 * message can be accessed:
 *
 *   dsos_msg_t *msg = req->msg;
 *   msg->hdr.type = DSOS_PING_REQ;
 *   // fill in remaining message fields...
 *
 * Once the message has been formatted, it can be sent:
 *
 *   // conn is the connection object for the destination server
 *   err = dsos_req_submit(req, conn, len);
 *
 * The send is asynchronous. The DSOS server destined for the message
 * will send a response message which contains the same 64-bit message ID
 * as the request. This layer uses a red-black tree to match up these
 * IDs. It is an error for a response message to be received that cannot
 * be matched with a request message.
 *
 * When the response message arrives, the callback specified in
 * the dsos_req_new call is called:
 *
 *   void my_callback(dsos_req_t *req, size_t len, void *ctxt);
 *
 * The response message is in req->resp.
 *
 * The request object must be freed when no longer needed:
 *
 *   dsos_req_put(req);
 *
 * Requests to multiple servers are similar -- a dsos_req_all_t is first
 * allocated, then individual requests to one or more servers can be
 * accessed, then submitted. When submitted, one or more messages are
 * sent out. Response messages are matched up and an internal callback
 * counts them and when the last one is received, the callback specified
 * in the dsos_req_all_new() call is called.
 */

#include <assert.h>
#include <errno.h>
#include "dsos_priv.h"

static struct rbt	req_rbt;
static pthread_mutex_t	req_rbt_lock;
static uint64_t		req_next_id = 666;

static void		req_all_cb(dsos_req_t *req, size_t len, void *ctxt);

static int req_rbn_cmp_fn(void *tree_key, void *key)
{
	return (uint64_t)tree_key - (uint64_t)key;
}

void dsos_req_init(void)
{
	pthread_mutex_init(&req_rbt_lock, 0);
	rbt_init(&req_rbt, req_rbn_cmp_fn);
}

dsos_req_t *dsos_req_new(dsos_req_cb_t cb, void *ctxt)
{
	dsos_req_t	*req;
	dsosd_msg_t	*msg;

	req = malloc(sizeof(dsos_req_t));
	msg = malloc(zap_max_msg(g.zap));
	if (!req || !msg)
		dsos_fatal("out of memory");
	req->msg_len_max = zap_max_msg(g.zap);
	req->msg_len     = 0;
	req->refcount    = 1;
	req->ctxt        = ctxt;
	req->id          = req_next_id++;
	req->cb          = cb;
	req->msg         = msg;
	req->resp        = NULL;
	req->conn        = NULL;
	req->flags       = 0;
	req->msg->u.hdr.id     = req->id;
	req->msg->u.hdr.status = 0;
	req->msg->u.hdr.flags  = 0;
	sem_init(&req->sem, 0, 0);
	dsos_debug("req %p id %ld msg %p ctxt %p\n", req, req->id, req->msg, req->ctxt);
	return req;
}

int dsos_req_submit(dsos_req_t *req, dsos_conn_t *conn, size_t len)
{
	zap_err_t	zerr;
	struct req_rbn	*rbn;

	if (len > req->msg_len_max)
		return ZAP_ERR_PARAMETER;

	req->conn = conn;
	req->msg->u.hdr.id = req->id;

	rbn = calloc(1, sizeof(struct req_rbn));
	if (!rbn)
		dsos_fatal("out of memory");

	rbn->rbn.key = (void *)req->id;
	rbn->req = req;

	pthread_mutex_lock(&req_rbt_lock);
	rbt_ins(&req_rbt, (void *)rbn);
	pthread_mutex_unlock(&req_rbt_lock);

	dsos_debug("req %p srv %d %s id %ld conn %p msg %p len %d\n", req,
		   conn->server_id, dsos_msg_type_to_str(req->msg->u.hdr.type),
		   req->id, conn, req->msg, len);

	/* Wait for resources if necessary. */
	sem_wait(&conn->flow_sem);

	zerr = zap_send(conn->ep, req->msg, len);
	if (zerr != ZAP_ERR_OK)
		dsos_error("zap_send error %s len %d\n", zap_err_str(zerr), len);

	/*
	 * Consider req->msg to now be invalid. In this initial implementation, it
	 * points to a buffer malloc()'d above in dsos_req_new(), but eventually
	 * it will be a zap send buffer that must not be touched after the zap_send
	 * is posted.
	 */

	return zerr;
}

dsos_req_t *dsos_req_find(dsosd_msg_t *resp)
{
	struct req_rbn	*rbn;
	dsos_req_t	*req;

	pthread_mutex_lock(&req_rbt_lock);
	rbn = (struct req_rbn *)rbt_find(&req_rbt, (void *)resp->u.hdr.id);
	if (rbn) {
		req = rbn->req;
		if (req == NULL) dsos_fatal("req == NULL\n");
		req->resp = resp;
		rbt_del(&req_rbt, (struct rbn *)rbn);
		free(rbn);
		pthread_mutex_unlock(&req_rbt_lock);
		sem_post(&req->conn->flow_sem);
		return req;
	} else {
		pthread_mutex_unlock(&req_rbt_lock);
		return NULL;
	}
}

void dsos_req_get(dsos_req_t *req)
{
	ods_atomic_inc(&req->refcount);
}

void dsos_req_put(dsos_req_t *req)
{
	if (!ods_atomic_dec(&req->refcount)) {
		dsos_debug("req %p msg %p resp %p freed\n", req, req->msg, req->resp);
		if (req->msg)
			free(req->msg);
		free(req);
	}
}

dsos_req_all_t *dsos_req_all_new(dsos_req_all_cb_t cb, void *ctxt)
{
	int		i;
	dsos_req_all_t	*req_all;
	dsos_req_t	**reqs;
	dsosd_msg_t	*msg;

	req_all = calloc(1, sizeof(dsos_req_all_t));
	msg     = malloc(zap_max_msg(g.zap));
	reqs    = malloc(g.num_servers * sizeof(dsos_req_t *));
	if (!req_all || !msg || !reqs)
		dsos_fatal("out of memory");
	req_all->num_servers   = g.num_servers;
	req_all->msg_len_max   = zap_max_msg(g.zap);
	req_all->refcount      = 1;
	req_all->ctxt          = ctxt;
	req_all->cb            = cb;
	req_all->reqs          = reqs;
	req_all->num_reqs_pend = 0;
	sem_init(&req_all->sem, 0, 0);
	for (i = 0; i < g.num_servers; ++i)
		req_all->reqs[i] = dsos_req_new(req_all_cb, req_all);

	dsos_debug("req_all %p\n", req_all);

	return req_all;
}

dsos_req_all_t *dsos_req_all_sparse_new(dsos_req_all_cb_t cb, void *ctxt)
{
	int		i;
	dsos_req_all_t	*req_all;
	dsos_req_t	**reqs;
	dsosd_msg_t	*msg;

	req_all = calloc(1, sizeof(dsos_req_all_t));
	msg     = malloc(zap_max_msg(g.zap));
	reqs    = calloc(g.num_servers, sizeof(dsos_req_t *));
	if (!req_all || !msg || !reqs)
		dsos_fatal("out of memory");
	req_all->msg_len_max   = zap_max_msg(g.zap);
	req_all->refcount      = 1;
	req_all->ctxt          = ctxt;
	req_all->cb            = cb;
	req_all->reqs          = reqs;
	req_all->num_reqs_pend = 0;
	req_all->num_servers   = 0;
	sem_init(&req_all->sem, 0, 0);

	dsos_debug("req_all %p\n", req_all);

	return req_all;
}

dsos_req_t *dsos_req_all_add_server(dsos_req_all_t *req_all, int server_num)
{
	if (req_all->reqs[server_num])
		return req_all->reqs[server_num];

	++req_all->num_servers;

	dsos_debug("req_all %p add server %d num_servers %d\n",
		   req_all, server_num, req_all->num_servers);

	req_all->reqs[server_num] = dsos_req_new(req_all_cb, req_all);
	if (!req_all->reqs[server_num])
		dsos_fatal("out of memory\n");
	return req_all->reqs[server_num];
}

void dsos_req_all_put(dsos_req_all_t *req_all)
{
	int	i;

	if (!ods_atomic_dec(&req_all->refcount)) {
		dsos_debug("req_all %p freeing, %d servers\n", req_all, req_all->num_servers);
		for (i = 0; i < g.num_servers; ++i) {
			if (req_all->reqs[i])
				dsos_req_put(req_all->reqs[i]);
		}
		free(req_all->reqs);
		free(req_all);
	}
}

int dsos_req_all_submit(dsos_req_all_t *req_all, size_t len)
{
	int		i, ret = 0;
	dsos_req_t	*req;
	dsosd_msg_t	*msg;

	dsos_debug("req_all %p for %d servers len %d\n", req_all, req_all->num_servers, len);

	req_all->num_reqs_pend = req_all->num_servers;
	dsos_err_clear();
	for (i = 0; i < g.num_servers; ++i) {
		req = req_all->reqs[i];
		if (!req || (req->msg->u.hdr.type == DSOSD_MSG_INVALID))
			continue;
		if (!req->msg_len)
			req->msg_len = len;
		ret = dsos_req_submit(req_all->reqs[i], &g.conns[i], req->msg_len);
		if (ret)
			dsos_fatal("ret %d\n", ret);
		dsos_err_set(i, ret);
	}
	return dsos_err_status();
}

static void req_all_cb(dsos_req_t *req, size_t len, void *ctxt)
{
	dsosd_msg_t	*resp;
	dsos_req_all_t	*req_all = (dsos_req_all_t *)ctxt;

	/*
	 * The req->resp response buffer is invalid after this function
	 * returns, so copy it. This is acceptable because these are
	 * not part of any fast-path operations.
	 */
	if (req->resp && len) {
		resp = (dsosd_msg_t *)malloc(len);
		if (!resp)
			dsos_fatal("out of memory\n");
		memcpy(resp, req->resp, len);
	} else
		resp = NULL;

	req->resp = resp;

#ifdef DSOS_DEBUG
	if (resp) {
		dsos_debug("req %p req_all %p pend %d len %d ctxt %p msg %p id %ld "
			   "type %d status %d copied to %p\n",
			   req, req_all, req_all->num_reqs_pend,
			   len, ctxt, req->msg, resp->u.hdr.id,
			   resp->u.hdr.type, resp->u.hdr.status, resp);
	} else {
		dsos_debug("req %p req_all %p len %d ctxt %p flushed\n",
			   req, req_all, len, ctxt);
	}
#endif

	if (!ods_atomic_dec(&req_all->num_reqs_pend)) {
		req_all->cb(req_all, req_all->ctxt);
		/* Note: the callback above is responsible for the dsos_req_all_put(req_all). */
	}
	dsos_debug("done\n");
}

/*
 * The DSOS request layer sends "request" messages to one or more
 * servers and matches them up with "response" messages that later
 * arrive.  A request or response message is a 2k-byte buffer of
 * formatted data represented as a large union of C structures defined
 * in dsos/server/dsos_msg_layout.h.  The RPC layer, which sits above
 * this layer, marshalls arguments into these messages to create a
 * server request. This layer sees them as blobs except that it looks
 * inside to set and read the message "id." Every request carries a
 * client-unique 64-bit id that the server reflects back in its
 * response message.  The code in this file uses this id to match
 * request and response.
 *
 * To send a request to a single server, or to all servers, a dsos_req_t
 * is first allocated:
 *
 *   dsos_req_t *req_one = dsos_req_new(DSOS_REQ_ONE, callback_fn, ctxt);
 *   dsos_req_t *req_all = dsos_req_new(DSOS_REQ_ALL, callback_fn, ctxt);
 *
 * By requiring allocation, this layer can support transports that
 * directly provide their buffers, thereby avoiding a copy.
 * With DSOS_REQ_ALL, g.num_servers request message buffers are allocated;
 * with DSOS_REQ_ONE, one is allocated.
 *
 * The request message then can be filled in. For a single server:
 *
 *   dsos_msg_t *msg = req->buf->send.msg;
 *   msg->hdr.type = DSOS_PING_REQ;
 *   // fill in remaining message fields...
 *   // ...
 *   req->buf->send.len = sizeof(dsosd_msg_ping_req_t);
 *   dsos_req_set_server(req, server_num_to_send_to);
 *
 * For DSOS_REQ_ALL, use a loop:
 *
 *   for (i = 0; i < g.num_servers; ++i) {
 *       msg = (dsosd_msg_ping_req_t *)req->bufs[i].send.msg;
 *       msg->hdr.type = DSOSD_MSG_PING_REQ;
 *       req->bufs[i]->send.len = sizeof(dsosd_msg_ping_req_t);
 *   }
 *
 * Note that dsos_req_set_server() is not called in the DSOS_REQ_ALL case
 * since all servers are used.
 *
 * Once the message has been formatted, it can be sent:
 *
 *   err = dsos_req_send(flags, req);
 *
 * The flags are as follows and can be logically or'd together:
 *
 *   1. Flags for callback management: the callback_fn specified in the
 *      dsos_req_new() is called when a response message arrives for:
 *
 *        DSOS_REQ_CB_FIRST  - call on first response
 *        DSOS_REQ_CB_LAST   - call on last response
 *        DSOS_REQ_CB_ALL    - call on every response
 *        DSOS_REQ_CB        - shortcut for DSOS_REQ_CB_ALL
 *
 *      Note that callback functions occur on zap worker threads. This
 *      means that responses from different servers may be processed
 *      by concurrent threads.
 *
 *   2. Flags for waiting: the dsos_req_send() call is asynchronous unless
 *      the following flag is specified.
 *
 *        DSOS_REQ_WAIT
 *
 *      This does a sem_wait(req->sem) for each expected response. The
 *      sem_post()s are done after each callback. Thus, the caller will
 *      block until the last callback has returned.
 *
 * The DSOS server(s) destined for the requests(s) will send
 * response message(s) which contain the same 64-bit message IDs as the
 * request(s). The request layer uses a red-black tree to match up these
 * IDs. It is an error for a response message to be received that
 * cannot be matched with a request message. However, in the future
 * such unsolicited messages may be supported.
 *
 * Callback functions are like the following:
 *
 *   // The response message is in resp->msg; it's length is resp->len.
 *   // server_num is the server # of where it came from.
 *   // flags is a logical or of DSOS_REQ_CB_FIRST or DSOS_REQ_CB_LAST
 *   // and indicates whether this response is the first one seen so far
 *   // for the request, the last, or neither. Note that a response can be
 *   // both first and last.
 *   void callback_fn(dsos_req_t *req, dsos_req_flags_t flags, dsos_buf_t *resp,
 *                    int server_num, void *ctxt)
 *   {
 *      ....
 *     dsos_err_set_remote(req->status, server_num, msg->hdr.status);
 *   }
 *
 * The request object helps with surfacing both local and remote
 * status to the caller. Each DSOS request can have both local and
 * remote failures which are surfaced via two int vectors each of
 * g.num_servers elements. The global dsos_errno is a dsos_err_t which
 * encapsulates these vectors; see dsos_err.c for its API. When
 * dsos_req_send() runs, it collects any local errors in req->status
 * which also is a dsos_err_t. Remote errors can be added by the
 * caller's callback function; these errors have to be added to
 * req->status instead of dsos_errno since the latter is a
 * thread-local global and the callback runs on a different thread and
 * therefore sees a different dsos_errno. By putting status vectors
 * into req->status, the application and callback threads can collect
 * status in one place; then, just before dsos_req_send() returns, it
 * sets dsos_errno to req->status.
 *
 * When dsos_req_send() is done it returns a logical or of DSOS_ERR_LOCAL
 * or DSOS_ERR_REMOTE to indicate where non-0 status lies.
 *
 * The request object is automatically freed after the callback function
 * is called and dsos_req_send() returns. To keep the dsos_req_t object
 * accessible longer, use the put/get API:
 *
 *   dsos_req_get(req);
 *   dsos_req_put(req);
 */

#include <assert.h>
#include <errno.h>
#include "dsos_priv.h"

static struct rbt	req_rbt;
static pthread_mutex_t	req_rbt_lock;
static pthread_mutex_t	req_id_lock;
static uint64_t		req_next_id = 1;

static void		req_all_cb(dsos_req_t *req, size_t len, void *ctxt);

static int req_rbn_cmp_fn(void *tree_key, void *key)
{
	return (uint64_t)tree_key - (uint64_t)key;
}

void dsos_req_init(void)
{
	pthread_mutex_init(&req_id_lock, 0);
	pthread_mutex_init(&req_rbt_lock, 0);
	rbt_init(&req_rbt, req_rbn_cmp_fn);
}

dsos_req_t *dsos_req_new(dsos_req_flags_t flags, dsos_req_cb_t cb, void *ctxt)
{
	int		i, num_servers = (flags & DSOS_REQ_ONE) ? 1 : g.num_servers;
	dsos_req_t	*req;
	dsos_buf_t	buf;
	dsos_buf_t	null_buf = { NULL, 0, 0, NULL };

	req = malloc(sizeof(dsos_req_t));
	if (!req)
		dsos_fatal("out of memory");
	req->refcount    = 1;
	req->flags       = flags;
	req->status      = dsos_err_new();
	req->cb          = cb;
	req->ctxt        = ctxt;
	req->ctxt2.ptr1  = NULL;
	req->ctxt2.ptr2  = NULL;
	req->num_servers = num_servers;
	req->num_pend    = 0;
	req->bufs        = (dsos_req_bufs_t *)malloc(num_servers * sizeof(dsos_req_bufs_t));
	req->buf         = req->bufs;
	if (!req->bufs)
		dsos_fatal("out of memory");

	pthread_mutex_lock(&req_id_lock);
	dsos_debug("req %p ids %ld..%ld for %d server%s\n", req,
		   req_next_id, req_next_id+num_servers-1, num_servers, num_servers==1?"":"s");
	for (i = 0; i < num_servers; ++i) {
		buf.free_fn = free;
		buf.len     = 0;
		buf.max_len = zap_max_msg(g.zap);
		buf.msg     = malloc(buf.max_len);
		buf.msg->u.hdr.id     = req_next_id++;
		buf.msg->u.hdr.status = 0;
		buf.msg->u.hdr.flags  = 0;
		req->bufs[i].send = buf;
		req->bufs[i].resp = null_buf;
	}
	pthread_mutex_unlock(&req_id_lock);

	sem_init(&req->sem, 0, 0);

	return req;
}

void dsos_req_get(dsos_req_t *req)
{
	ods_atomic_inc(&req->refcount);
}

void dsos_req_put(dsos_req_t *req)
{
	int	i;

	if (!ods_atomic_dec(&req->refcount)) {
		dsos_debug("freeing req %p flags 0x%x num_servers %d\n", req, req->flags, req->num_servers);
		for (i = 0; i < req->num_servers; ++i) {
			if (req->bufs[i].send.free_fn && req->bufs[i].send.msg)
				req->bufs[i].send.free_fn(req->bufs[i].send.msg);
			if (req->bufs[i].resp.free_fn && req->bufs[i].resp.msg)
				req->bufs[i].resp.free_fn(req->bufs[i].resp.msg);
		}
		free(req->bufs);
		free(req);
	}
}

void dsos_req_set_server(dsos_req_t *req, int server_num)
{
	req->server_num = server_num;
}

int dsos_req_send(dsos_req_flags_t flags, dsos_req_t *req)
{
	int		i, n, server_num;
	zap_err_t	zerr;
	zap_ep_t	ep;
	dsos_conn_t	*conn;
	struct req_rbn	*rbn;

	req->flags   |= flags;
	req->num_pend = req->num_servers;

	/*
	 * This reference must be taken to keep the req from being freed
	 * until after the sem_wait() calls done below return.
	 */
	dsos_req_get(req);

	for (i = 0; i < req->num_servers; ++i) {
		if (req->bufs[i].send.len > req->bufs[i].send.max_len) {
			dsos_err_set_local(req->status, i, ZAP_ERR_PARAMETER);
			continue;
		}

		server_num = (req->num_servers == 1) ? req->server_num : i;
		conn = &g.conns[server_num];

		rbn = calloc(1, sizeof(struct req_rbn));
		if (!rbn)
			dsos_fatal("out of memory");
		rbn->rbn.key = (void *)req->bufs[i].send.msg->u.hdr.id;
		rbn->req = req;

		pthread_mutex_lock(&req_rbt_lock);
		rbt_ins(&req_rbt, (void *)rbn);
		pthread_mutex_unlock(&req_rbt_lock);

		dsos_debug("req %p server %d %s id %ld ep %p msg %p len %d\n", req, server_num,
			   dsos_msg_type_to_str(req->bufs[i].send.msg->u.hdr.type),
			   req->bufs[i].send.msg->u.hdr.id,
			   conn->ep, req->bufs[i].send.msg, req->bufs[i].send.len);

		/* Wait for resources if necessary. */
		sem_wait(&conn->flow_sem);

		zerr = zap_send(conn->ep, req->bufs[i].send.msg, req->bufs[i].send.len);
		if (zerr != ZAP_ERR_OK)
			dsos_error("send err %d (%s) server %d ep %p len %d\n",
				   zerr, zap_err_str(zerr), server_num, conn->ep, req->bufs[i].send.len);
		dsos_err_set_local(req->status, i, zerr);
	}
	if (dsos_err_status(req->status) & DSOS_ERR_LOCAL) {
		dsos_req_put(req);
		return DSOS_ERR_LOCAL;
	}

	if (req->flags & DSOS_REQ_WAIT) {
		dsos_debug("waiting\n");
		for (i = 0; i < req->num_servers; ++i)
			sem_wait(&req->sem);
		dsos_debug("wait complete\n");
	}

	dsos_err_free(dsos_errno);
	dsos_errno = req->status;

	dsos_req_put(req);  /* free the ref taken above */

	return 0;
}

void dsos_req_handle_resp(dsos_conn_t *conn, dsosd_msg_t *resp, size_t len)
{
	int		first, last, responses_left;
	uint32_t	flags;
	struct req_rbn	*rbn;
	dsos_req_t	*req;
	dsos_req_bufs_t	*buf;

	pthread_mutex_lock(&req_rbt_lock);
	rbn = (struct req_rbn *)rbt_find(&req_rbt, (void *)resp->u.hdr.id);
	if (!rbn) {
		pthread_mutex_unlock(&req_rbt_lock);
		dsos_fatal("no req for id %ld from server %d\n", resp->u.hdr.id, conn->server_id);
	}
	rbt_del(&req_rbt, (struct rbn *)rbn);
	pthread_mutex_unlock(&req_rbt_lock);

	sem_post(&conn->flow_sem);

	req = rbn->req;
	if (req->num_servers == 1)
		buf = req->buf;
	else
		buf = &req->bufs[conn->server_id];

	buf->resp.msg     = resp;
	buf->resp.free_fn = NULL;
	buf->resp.max_len = len;
	buf->resp.len     = len;

	responses_left = ods_atomic_dec(&req->num_pend);

	dsos_debug("msg %s id %ld status %d from server %d resp %p/%d %d responses of %d left\n",
		   dsos_msg_type_to_str(resp->u.hdr.type), resp->u.hdr.id, resp->u.hdr.status,
		   conn->server_id, resp, len, responses_left, req->num_servers);

	first = (responses_left == req->num_servers-1);
	last  = (responses_left == 0);

	flags = 0;
	if (first) flags |= DSOS_REQ_CB_FIRST;
	if (last)  flags |= DSOS_REQ_CB_LAST;

	if ((flags & req->flags) || DSOS_REQ_CB_ALL)
		req->cb(req, flags, &buf->resp, conn->server_id, req->ctxt);
	sem_post(&req->sem);
	if (last)
		dsos_req_put(req);
	free(rbn);
	dsos_debug("done\n");
}

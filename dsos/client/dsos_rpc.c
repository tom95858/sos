/*
 * The DSOS RPC layer sends "request" messages to one or more servers
 * and matches them up with "response" messages that later arrive.
 * A message is a variable-length buffer consisting of a small
 * fixed-sized header (defined in dsos_rpc_msg.h) followed by
 * serialized data specific to the RPC.  The header contains the RPC
 * type and a client-unique 64-bit id that the server reflects back in
 * its response message. The RPC layer uses this id to match request
 * and response. RPC requests or responses larger than the transport
 * message size are split across multiple transport messages.
 *
 * 1. CREATE RPC REQUEST
 *
 * To send a request to a single server, or to all servers, a dsos_rpc_t
 * is first allocated:
 *
 *   dsos_rpc_t *rpc_one = dsos_rpc_new(DSOS_REQ_ONE, dsos_rpc_type_t rpc_type);
 *   dsos_rpc_t *rpc_all = dsos_rpc_new(DSOS_REQ_ALL, dsos_rpc_type_t rpc_type);
 *
 * By requiring allocation, this layer can support transports that
 * directly provide their buffers, thereby avoiding a copy.  With
 * DSOS_REQ_ALL, g.num_servers request message buffers are allocated;
 * with DSOS_REQ_ONE, one is allocated.  The request buffers initially
 * are sized to be the zap transport's maximum message size, but the
 * buffer is dynamnically grown as data is serialized into the request
 * as described next.
 *
 * The request is constructed by calling helper functions
 * which call into the dsos_pack_xxx/dsos_unpack_xxx library to
 * serialize and deserialize data structures in to and out of the
 * request buffer (pack operations) or response buffer (unpack):
 *
 *   void dsos_rpc_pack_u32_one(rpc, uint32_t);
 *   void dsos_rpc_pack_u32_all(rpc, uint32_t);
 *   void dsos_rpc_pack_u64_one(rpc, uint64_t);
 *   void dsos_rpc_pack_u64_all(rpc, uint64_t);
 *   void dsos_rpc_pack_str_one(rpc, const char *);
 *   void dsos_rpc_pack_str_all(rpc, const char *);
 *   void dsos_rpc_pack_key_one(rpc, sos_key_t);
 *   void dsos_rpc_pack_key_all(rpc, sos_key_t);
 *   void dsos_rpc_pack_schema_all(rpc, sos_schema_t);
 *   void dsos_rpc_pack_obj(rpc, sos_obj_t);
 *   void dsos_rpc_pack_obj_ptr(rpc, sos_obj_t);
 *   void dsos_rpc_pack_obj_id_one(rpc, sos_obj_ref_t);
 *   void dsos_rpc_pack_obj_id_all(rpc, sos_obj_ref_t);
 *   void dsos_rpc_pack_handle(rpc, dsos_handle_t);
 *   ... (see dsos_pack.c for the most up-to-date list)
 *
 * The _one variants are used for DSOS_REQ_ONE and the _all variants
 * are used for DSOS_REQ_ALL where the given value is serialized to
 * all request buffers (one per server).
 *
 * To faciliate passing vectors, the following take an array of
 * pointers to handles or objects and serialize them across the
 * request buffers for all servers:
 *
 *   void dsos_rpc_pack_handles(rpc, dsos_handle_t *);
 *   void dsos_rpc_pack_obj_ptrs(rpc, sos_obj_t *);
 *
 * To discover whether len bytes can still be serialized into the
 * request (DSOS_REQ_ONE only):
 *
 *   int dsos_rpc_pack_fits(rpc, int len);
 *
 * To see how many bytes an object's serialization would need (used to
 * determine when an object can be sent in-line in the request):
 *
 *   int dsos_rpc_pack_obj_needs(rpc, sos_obj_t);
 *
 * If a pack operation cannot be completed due to insufficient
 * space remaining in a request buffer, the rpc->status vector is
 * updated with a local status of E2BIG for the involved server(s).
 * Subsequent pack operations then are no-ops.
 *
 * Unpacking is done with an analogous API and operates on the
 * response buffer.
 *
 * 2. SEND RPC REQUEST
 *
 * Once the request has been fully created, it can be sent by one of the
 * following:
 *
 *   ret = dsos_rpc_send(rpc, flags);
 *   ret = dsos_rpc_send_one(rpc, flags, server_num);
 *   ret = dsos_rpc_send_cb(rpc, flags, callback_fn, callback_ctxt);
 *
 * The first form is for DSOS_REQ_ALL where all servers are sent the request.
 * The second form is for DSOS_REQ_ONE and takes the server_num. Another way
 * to specify the server_num is
 *
 *   dsos_req_set_server(req, server_num_to_send_to);
 *
 * which is necessary when using the third form to specify a callback.
 * (There is no API to specify both the server_num and the callback.)
 *
 * The flags are as follows and can be logically or'd together:
 *
 *   1. Flags for callback management: the callback_fn is called when
 *      a response message arrives if the following are specified:
 *
 *        DSOS_RPC_CB_FIRST  - call on first response
 *        DSOS_RPC_CB_LAST   - call on last response
 *        DSOS_RPC_CB_ALL    - call on every response
 *        DSOS_RPC_CB        - shortcut for DSOS_RPC_CB_ALL
 *
 *      Note that callback functions occur on zap worker threads. This
 *      means that responses from different servers may be processed
 *      by concurrent threads. Furthermore, the response message buffer
 *      becomes invalid after the callback returns (because it is a
 *      pointer to the zap receive buffer).
 *
 *   2. Flags for buffer management: sometimes it is convenient to have
 *      the response message(s) copied by the RPC layer so that the results
 *      can be accessed after the callback functions return (or perhaps
 *      it is easier to not use a callback).  The following flag causes
 *      response buffers to be copied. They remain valid until the RPC
 *      object is freed:
 *
 *        DSOS_RPC_PERSIST_RESPONSES
 *
 *   3. Flags for waiting: the dsos_rpc_send() call is asynchronous unless
 *      the following flag is specified.
 *
 *        DSOS_RPC_WAIT
 *
 *      This does a sem_wait(rpc->sem) for each expected response. The
 *      sem_post()s are done after each callback. Thus, the caller will
 *      block until the last callback has returned.
 *
 *   4. Flags for cleanup: the dsos_rpc_t object is reference counted
 *      and begins with one reference which either must be
 *      dsos_req_put() by the caller or be put by specifying
 *
 *        DSOS_RPC_PUT
 *
 * RPCs are flow-controlled using a credit system. Currently up to
 * four RPCs per server connection can be outstanding. This value
 * could be easily made into a config parameter. A credit must be
 * obtained to send an RPC and a credit is reclaimed when an RPC
 * response is received.  The caller is blocked on
 * conn->rpc_credit_sem if necessary, until a response has been
 * received to an earlier RPC to the server. All of this is handled
 * inside the RPC layer. Just note that dsos_rpc_send() can block.
 *
 * Each DSOS server destined for the request(s) will send a response
 * message which contains the same 64-bit message ID as the
 * request. In an RPC vector, each request gets a different ID (i.e.,
 * each server sees a different ID). The RPC layer uses a red-black
 * tree to match up these IDs. It is an error for a response message
 * to be received that cannot be matched with a request
 * message. However, in the future such unsolicited messages may be
 * supported.
 *
 * 3. PROCESS RPC RESULTS
 *
 * There are two ways to handle the response message(s) which come back
 * from the server(s). One is to use callback functions which unpack
 * results from the response buffer(s) as they arrive. Another is to
 * use the DSOS_RPC_PERSIST_RESPONSES flag along with DSOS_RPC_WAIT
 * and unpack the responses after dsos_rpc_send() returns.
 *
 * Callback functions are like the following:
 *
 *   // The response message is in resp->msg; it's length is resp->len.
 *   // server_num is the server # of where it came from.
 *   // flags is a logical or of DSOS_REQ_CB_FIRST or DSOS_REQ_CB_LAST
 *   // and indicates whether this response is the first one seen so far
 *   // for the request, the last, or neither. Note that a response can be
 *   // both first and last.
 *   void callback_fn(dsos_rpc_t *rpc, dsos_rpc_flags_t flags, dsos_buf_t *resp,
 *                    int server_num, void *ctxt)
 *   {
 *      ....
 *     dsos_err_set_remote(rpc->status, server_num, msg->hdr.status);
 *   }
 *
 * The RPC object helps to surface both local and remote status to the
 * caller. Each DSOS request can have both local and remote failures
 * which are surfaced via two int vectors each of g.num_servers
 * elements. The global dsos_errno is a dsos_err_t which encapsulates
 * these vectors; see dsos_err.c for its API. When dsos_rpc_send()
 * runs, it collects any local errors in rpc->status which also is a
 * dsos_err_t. Remote errors can be added by the caller's callback
 * function; these errors have to be added to rpc->status instead of
 * dsos_errno since the latter is a thread-local global and the
 * callback runs on a different thread and therefore sees a different
 * dsos_errno. By putting status vectors into rpc->status, the
 * application and callback threads can collect status in one place;
 * then, just before dsos_rpc_send() returns, it sets dsos_errno to
 * rpc->status.
 *
 * When dsos_rpc_send() is done it returns a logical or of DSOS_ERR_LOCAL
 * or DSOS_ERR_REMOTE to indicate where non-0 status lies.
 *
 * The request object is automatically freed after the callback function
 * is called and dsos_rpc_send() returns. To keep the dsos_rpc_t object
 * accessible longer, use the put/get API:
 *
 *   dsos_req_get(req);
 *   dsos_req_put(req);
 */

#include <assert.h>
#include <errno.h>
#include "dsos_priv.h"

static struct rbt	rpc_rbt;
static pthread_mutex_t	rpc_rbt_lock;
static pthread_mutex_t	rpc_id_lock;
static uint64_t		rpc_next_id = 1;

static int rpc_rbn_cmp_fn(void *tree_key, void *key)
{
	return (uint64_t)tree_key - (uint64_t)key;
}

void dsos_rpc_init(void)
{
	pthread_mutex_init(&rpc_id_lock, 0);
	pthread_mutex_init(&rpc_rbt_lock, 0);
	rbt_init(&rpc_rbt, rpc_rbn_cmp_fn);
}

dsos_rpc_t *dsos_rpc_new(dsos_rpc_flags_t flags, dsos_rpc_type_t type)
{
	int		i, num_servers = (flags & DSOS_RPC_ONE) ? 1 : g.num_servers;
	dsos_rpc_t	*rpc;
	dsos_buf_t	buf;
	dsos_buf_t	null_buf = {
		.msg        = NULL,
		.allocated  = 0,
		.len        = 0,
		.free_fn    = NULL,
		.p          = NULL
	};

	rpc = dsos_malloc(sizeof(dsos_rpc_t));
	rpc->refcount    = 1;
	rpc->flags       = flags;
	rpc->status      = dsos_err_new();
	rpc->cb          = NULL;
	rpc->ctxt        = NULL;
	rpc->ctxt2.ptr1  = NULL;
	rpc->ctxt2.ptr2  = NULL;
	rpc->num_servers = num_servers;
	rpc->num_pend    = 0;
	rpc->bufs        = (dsos_rpc_bufs_t *)dsos_malloc(num_servers * sizeof(dsos_rpc_bufs_t));
	rpc->buf         = rpc->bufs;

	pthread_mutex_lock(&rpc_id_lock);
	dsos_debug("rpc %p ids %ld..%ld for %d server%s\n", rpc,
		   rpc_next_id, rpc_next_id+num_servers-1, num_servers,
		   rpc->flags & DSOS_RPC_ONE?"":"s");
	for (i = 0; i < num_servers; ++i) {
		buf.free_fn    = free;
		buf.len        = sizeof(dsos_msg_t);
		buf.allocated  = zap_max_msg(g.zap);
		buf.msg        = malloc(buf.allocated);
		buf.p          = (char *)(buf.msg + 1);
		buf.msg->hdr.id     = rpc_next_id++;
		buf.msg->hdr.type   = type;
		buf.msg->hdr.flags  = 0;
		buf.msg->hdr.status = 0;
		rpc->bufs[i].req  = buf;
		rpc->bufs[i].resp = null_buf;
	}
	pthread_mutex_unlock(&rpc_id_lock);

	sem_init(&rpc->sem, 0, 0);

	return rpc;
}

void dsos_rpc_get(dsos_rpc_t *rpc)
{
	ods_atomic_inc(&rpc->refcount);
}

void dsos_rpc_put(dsos_rpc_t *rpc)
{
	int	i;

	if (!ods_atomic_dec(&rpc->refcount)) {
		dsos_debug("freeing rpc %p flags 0x%x num_servers %d\n", rpc, rpc->flags, rpc->num_servers);
		for (i = 0; i < rpc->num_servers; ++i) {
			if (rpc->bufs[i].req.free_fn && rpc->bufs[i].req.msg) {
				rpc->bufs[i].req.free_fn(rpc->bufs[i].req.msg);
			}
			if (rpc->bufs[i].resp.free_fn && rpc->bufs[i].resp.msg)
				rpc->bufs[i].resp.free_fn(rpc->bufs[i].resp.msg);
		}
		if (rpc->flags & DSOS_RPC_FREE_STATUS)
			dsos_err_free(rpc->status);
		free(rpc->bufs);
		free(rpc);
	}
}

void dsos_rpc_set_server(dsos_rpc_t *rpc, int server_num)
{
	rpc->server_num = server_num;
}

int dsos_rpc_send_one(dsos_rpc_t *rpc, dsos_rpc_flags_t flags, int server_num)
{
	rpc->server_num = server_num;
	return dsos_rpc_send(rpc, flags);
}

int dsos_rpc_send_cb(dsos_rpc_t *rpc, dsos_rpc_flags_t flags, dsos_rpc_cb_t cb, void *ctxt)
{
	rpc->cb   = cb;
	rpc->ctxt = ctxt;
	return dsos_rpc_send(rpc, flags);
}

int dsos_rpc_send(dsos_rpc_t *rpc, dsos_rpc_flags_t flags)
{
	int		i, n, ret, server_num, to_send;
	uint32_t	len;
	char		*frame;
	zap_err_t	zerr;
	zap_ep_t	ep;
	dsos_conn_t	*conn;
	struct rpc_rbn	*rbn;

	/*
	 * Fail immediately if rpc->status contains any local
	 * errors. This means there was an error during argument
	 * packing.
	 */
	ret = dsos_err_status(rpc->status);
	if (ret) {
		dsos_err_free(dsos_errno);
		dsos_errno = rpc->status;
		return dsos_err_status(dsos_errno);
	}

	rpc->flags   |= flags;
	rpc->num_pend = rpc->num_servers;

	/*
	 * This reference must be taken to keep the rpc from being freed
	 * until after the sem_wait() calls done below return.
	 */
	dsos_rpc_get(rpc);

	for (i = 0; i < rpc->num_servers; ++i) {
		if (rpc->bufs[i].req.len > rpc->bufs[i].req.allocated) {
			dsos_err_set_local(rpc->status, i, ZAP_ERR_PARAMETER);
			continue;
		}

		server_num = (rpc->flags & DSOS_RPC_ONE) ? rpc->server_num : i;
		conn = &g.conns[server_num];

		rbn = dsos_calloc(1, sizeof(struct rpc_rbn));
		rbn->rbn.key = (void *)rpc->bufs[i].req.msg->hdr.id;
		rbn->rpc = rpc;

		pthread_mutex_lock(&rpc_rbt_lock);
		rbt_ins(&rpc_rbt, (void *)rbn);
		pthread_mutex_unlock(&rpc_rbt_lock);

		dsos_debug("rpc %p server %d %s id %ld ep %p msg %p len %d\n", rpc, server_num,
			   dsos_rpc_type_to_str(rpc->bufs[i].req.msg->hdr.type),
			   rpc->bufs[i].req.msg->hdr.id,
			   conn->ep, rpc->bufs[i].req.msg, rpc->bufs[i].req.len);

		/* Wait for resources if necessary. */
		sem_wait(&conn->rpc_credit_sem);

#ifdef RPC_DEBUG
		{
		char *s;

		asprintf(&s, "Req to server %d:", i);
		dsos_buf_dump(stdout, &rpc->bufs[i].req, s);
		free(s);
		}
#endif
		len = rpc->bufs[i].req.len;
		rpc->bufs[i].req.msg->hdr.len = len;

		if (len > zap_max_msg(g.zap)) {
			dsos_debug("len %d sending as multiple\n", len);
			rpc->bufs[i].req.msg->hdr.flags |= DSOS_RPC_FLAGS_MULTIPLE;
		}

		frame = (char *)rpc->bufs[i].req.msg;
		while (len > 0) {
			to_send = len > zap_max_msg(g.zap) ? zap_max_msg(g.zap) : len;
			zerr = zap_send(conn->ep, frame, to_send);
			if (zerr != ZAP_ERR_OK) {
				dsos_error("send err %d (%s) server %d ep %p len %d\n", zerr,
					   zap_err_str(zerr), server_num, conn->ep, to_send);
				dsos_err_set_local(rpc->status, i, zerr);
				break;
			}
			frame += to_send;
			len   -= to_send;
		}
	}
	if (dsos_err_status(rpc->status) & DSOS_ERR_LOCAL) {
		dsos_err_free(dsos_errno);
		dsos_errno = rpc->status;
		dsos_rpc_put(rpc);
		return DSOS_ERR_LOCAL;
	}
	ret = 0;

	if (rpc->flags & DSOS_RPC_WAIT) {
		dsos_debug("waiting\n");
		for (i = 0; i < rpc->num_servers; ++i)
			sem_wait(&rpc->sem);
		dsos_err_free(dsos_errno);
		dsos_errno = rpc->status;
		ret = dsos_err_status(dsos_errno);
		dsos_debug("wait complete, status %d\n", ret);
	} else {
		rpc->flags |= DSOS_RPC_FREE_STATUS;
	}

	dsos_rpc_put(rpc);  /* free the ref taken above */

	return ret;
}

void dsos_rpc_handle_resp(dsos_conn_t *conn, dsos_msg_t *resp, size_t len)
{
	int			first, last, responses_left;
	dsos_rpc_flags_t	flags, rpc_flags;
	struct rpc_rbn		*rbn;
	dsos_rpc_t		*rpc;
	dsos_rpc_bufs_t		*buf;

	pthread_mutex_lock(&rpc_rbt_lock);
	rbn = (struct rpc_rbn *)rbt_find(&rpc_rbt, (void *)resp->hdr.id);
	if (!rbn) {
		pthread_mutex_unlock(&rpc_rbt_lock);
		dsos_fatal("no rpc for id %ld from server %d\n", resp->hdr.id, conn->server_id);
	}
	rbt_del(&rpc_rbt, (struct rbn *)rbn);
	pthread_mutex_unlock(&rpc_rbt_lock);

	sem_post(&conn->rpc_credit_sem);

	rpc = rbn->rpc;
	if (rpc->flags & DSOS_RPC_ONE)
		buf = rpc->buf;
	else
		buf = &rpc->bufs[conn->server_id];

	if (rpc->flags & DSOS_RPC_PERSIST_RESPONSES) {
		buf->resp.msg       = (dsos_msg_t *)dsos_malloc(len);
		buf->resp.free_fn   = free;
		buf->resp.allocated = len;
		buf->resp.len       = len;
		buf->resp.p         = (char *)(buf->resp.msg + 1);
		memcpy(buf->resp.msg, resp, len);
	} else {
		buf->resp.msg       = resp;
		buf->resp.free_fn   = NULL;
		buf->resp.allocated = len;
		buf->resp.len       = len;
		buf->resp.p         = (char *)(buf->resp.msg + 1);
	}

	responses_left = ods_atomic_dec(&rpc->num_pend);

	dsos_debug("msg %s id %ld status %d from server %d rpc %p resp %p/%d%s %d responses of %d left\n",
		   dsos_rpc_type_to_str(resp->hdr.type), resp->hdr.id, resp->hdr.status,
		   conn->server_id, rpc,
		   resp, len, rpc->flags & DSOS_RPC_PERSIST_RESPONSES ? " (copied)" : "",
		   responses_left, rpc->num_servers);
#ifdef RPC_DEBUG
	{
	char *s;

	asprintf(&s, "Response from server %d:", conn->server_id);
	dsos_buf_dump(stdout, &buf->resp, s);
	free(s);
	}
#endif
	dsos_err_set_remote(rpc->status, conn->server_id, resp->hdr.status);

	first = (responses_left == rpc->num_servers-1);
	last  = (responses_left == 0);

	flags = 0;
	if (first) flags |= DSOS_RPC_CB_FIRST;
	if (last)  flags |= DSOS_RPC_CB_LAST;

	/*
	 * Warning: the RPC object is freed in one of two ways and care must
	 * be taken to avoid dangling references below.
	 *
	 * First, the caller's callback can do the final dsos_rpc_put(),
	 * and in that case we assume flags does not contain DSOS_RPC_PUT
	 * or DSOS_RPC_WAIT. It is an error if the caller does otherwise.
	 * To allow for this, do not access rpc after the callback returns.
	 *
	 * Second, the caller can specify DSOS_RPC_PUT, and unless they have
	 * obtained another reference on rpc, the final put is done below.
	 */

	rpc_flags = rpc->flags;

	if (rpc->cb && ((flags & rpc->flags) || DSOS_RPC_CB_ALL))
		rpc->cb(rpc, flags, &buf->resp, conn->server_id, rpc->ctxt);
	if (rpc_flags & DSOS_RPC_WAIT)
		sem_post(&rpc->sem);
	if (last && (rpc_flags & DSOS_RPC_PUT))
		dsos_rpc_put(rpc);

	free(rbn);
	dsos_debug("done\n");
}

void dsos_rpc_pack_u32_one(dsos_rpc_t *rpc, uint32_t val)
{
	assert(rpc->flags & DSOS_RPC_ONE);

	if (dsos_pack_u32(&rpc->buf->req, val))
		dsos_err_set_local(rpc->status, rpc->server_num, E2BIG);
}

void dsos_rpc_pack_u32_all(dsos_rpc_t *rpc, uint32_t val)
{
	int	i, server_num;

	assert(rpc->flags & DSOS_RPC_ALL);

	for (i = 0; i < g.num_servers; ++i) {
		if (dsos_pack_u32(&rpc->bufs[i].req, val)) {
			server_num = (rpc->flags & DSOS_RPC_ONE) ? rpc->server_num : i;
			dsos_err_set_local(rpc->status, i, E2BIG);
		}
	}
}

void dsos_rpc_pack_u64_one(dsos_rpc_t *rpc, uint64_t val)
{
	assert(rpc->flags & DSOS_RPC_ONE);

	if (dsos_pack_u64(&rpc->buf->req, val))
		dsos_err_set_local(rpc->status, rpc->server_num, E2BIG);
}

void dsos_rpc_pack_u64_all(dsos_rpc_t *rpc, uint64_t val)
{
	int	i, server_num;

	assert(rpc->flags & DSOS_RPC_ALL);

	for (i = 0; i < g.num_servers; ++i) {
		if (dsos_pack_u64(&rpc->bufs[i].req, val)) {
			server_num = (rpc->flags & DSOS_RPC_ONE) ? rpc->server_num : i;
			dsos_err_set_local(rpc->status, i, E2BIG);
		}
	}
}

void dsos_rpc_pack_str_one(dsos_rpc_t *rpc, const char *str)
{
	assert(rpc->flags & DSOS_RPC_ONE);

	if (dsos_pack_str(&rpc->buf->req, str))
		dsos_err_set_local(rpc->status, rpc->server_num, E2BIG);
}

void dsos_rpc_pack_str_all(dsos_rpc_t *rpc, const char *str)
{
	int	i, server_num;

	assert(rpc->flags & DSOS_RPC_ALL);

	for (i = 0; i < g.num_servers; ++i) {
		if (dsos_pack_str(&rpc->bufs[i].req, str)) {
			server_num = (rpc->flags & DSOS_RPC_ONE) ? rpc->server_num : i;
			dsos_err_set_local(rpc->status, i, E2BIG);
		}
	}
}

uint32_t dsos_rpc_unpack_u32(dsos_rpc_t *rpc)
{
	assert(rpc->flags & DSOS_RPC_ONE);

	return dsos_unpack_u32(&rpc->buf->resp);
}

uint32_t dsos_rpc_unpack_u32_one(dsos_rpc_t *rpc, int server_num)
{
	assert(rpc->flags & DSOS_RPC_ALL);

	return dsos_unpack_u32(&rpc->buf[server_num].resp);
}

uint32_t dsos_rpc_unpack_u64(dsos_rpc_t *rpc)
{
	assert(rpc->flags & DSOS_RPC_ONE);

	return dsos_unpack_u64(&rpc->buf->resp);
}

char *dsos_rpc_unpack_str(dsos_rpc_t *rpc)
{
	assert(rpc->flags & DSOS_RPC_ONE);

	return dsos_unpack_str(&rpc->buf->resp);
}

void dsos_rpc_unpack_buf_and_copy(dsos_rpc_t *rpc, void *to, int *plen)
{
	int	len;
	char	*from = dsos_unpack_buf(&rpc->buf->resp, &len);
	assert(rpc->flags & DSOS_RPC_ONE);
	memcpy(to, from, len);
	if (plen)
		*plen = len;
}

void dsos_rpc_unpack_buf_and_copy_one(dsos_rpc_t *rpc, int server_num, void *to, int *plen)
{
	int	len;
	char	*from = dsos_unpack_buf(&rpc->bufs[server_num].resp, &len);
	assert(rpc->flags & DSOS_RPC_ALL);
	memcpy(to, from, len);
	if (plen)
		*plen = len;
}

void dsos_rpc_unpack_bufs_and_copy(dsos_rpc_t *rpc, void *to, int *plen)
{
	int	i, len;
	char	*from;

	assert(rpc->flags & DSOS_RPC_ALL);

	*plen = 0;
	for (i = 0; i < g.num_servers; ++i) {
		from = dsos_unpack_buf(&rpc->bufs[i].resp, &len);
		memcpy(to, from, len);
		to = (char *)to + len;
		*plen += len;
	}
}

void dsos_rpc_pack_obj_id_all(dsos_rpc_t *rpc, sos_obj_ref_t obj_id)
{
	int	i, ret, server_num;

	assert(rpc->flags & DSOS_RPC_ALL);

	for (i = 0; i < g.num_servers; ++i) {
		ret = dsos_pack_obj_id(&rpc->bufs[i].req, obj_id);
		if (ret) {
			server_num = (rpc->flags & DSOS_RPC_ONE) ? rpc->server_num : i;
			dsos_err_set_local(rpc->status, i, E2BIG);
		}
	}
}

void dsos_rpc_pack_obj_id_one(dsos_rpc_t *rpc, sos_obj_ref_t obj_id)
{
	int	ret;

	assert(rpc->flags & DSOS_RPC_ONE);

	ret = dsos_pack_obj_id(&rpc->buf->req, obj_id);
	if (ret)
		dsos_err_set_local(rpc->status, rpc->server_num, E2BIG);
}

sos_obj_ref_t dsos_rpc_unpack_obj_id(dsos_rpc_t *rpc)
{
	assert(rpc->flags & DSOS_RPC_ONE);

	return dsos_unpack_obj_id(&rpc->buf->resp);
}

sos_obj_ref_t dsos_rpc_unpack_obj_id_one(dsos_rpc_t *rpc, int server_num)
{
	assert(rpc->flags & DSOS_RPC_ALL);

	return dsos_unpack_obj_id(&rpc->bufs[server_num].resp);
}

void dsos_rpc_pack_handle(dsos_rpc_t *rpc, dsos_handle_t handle)
{
	int	ret;

	assert(rpc->flags & DSOS_RPC_ONE);

	ret = dsos_pack_handle(&rpc->buf->req, handle);
	if (ret)
		dsos_err_set_local(rpc->status, rpc->server_num, E2BIG);
}

void dsos_rpc_pack_handles(dsos_rpc_t *rpc, dsos_handle_t *handles)
{
	int	i, server_num;

	assert(rpc->flags & DSOS_RPC_ALL);

	for (i = 0; i < g.num_servers; ++i) {
		if (dsos_pack_u64(&rpc->bufs[i].req, handles[i])) {
			server_num = (rpc->flags & DSOS_RPC_ONE) ? rpc->server_num : i;
			dsos_err_set_local(rpc->status, i, E2BIG);
		}
	}
}

dsos_handle_t *dsos_rpc_unpack_handles(dsos_rpc_t *rpc)
{
	int		i;
	dsos_handle_t	*handles = (dsos_handle_t *)dsos_malloc(g.num_servers * sizeof(dsos_handle_t));

	assert(rpc->flags & DSOS_RPC_ALL);

	for (i = 0; i < g.num_servers; ++i)
		handles[i] = dsos_unpack_u64(&rpc->bufs[i].resp);
	return handles;
}

void dsos_rpc_pack_obj_ptrs(dsos_rpc_t *rpc, sos_obj_t *objs)
{
	int	i, ret, server_num;

	assert(rpc->flags & DSOS_RPC_ALL);

	for (i = 0; i < g.num_servers; ++i) {
		ret = dsos_pack_obj_ptr(&rpc->bufs[i].req, objs[i]);
		if (ret) {
			server_num = (rpc->flags & DSOS_RPC_ONE) ? rpc->server_num : i;
			dsos_err_set_local(rpc->status, i, E2BIG);
		}
	}
}

void dsos_rpc_pack_obj_ptr(dsos_rpc_t *rpc, sos_obj_t obj)
{
	int	ret, server_num;

	assert(rpc->flags & DSOS_RPC_ONE);

	ret = dsos_pack_obj_ptr(&rpc->buf->req, obj);
	if (ret)
		dsos_err_set_local(rpc->status, rpc->server_num, E2BIG);
}

void dsos_rpc_unpack_obj(dsos_rpc_t *rpc, sos_obj_t obj)
{
	assert(rpc->flags & DSOS_RPC_ONE);

	dsos_unpack_obj(&rpc->buf->resp, obj);
}

void dsos_rpc_unpack_obj_one(dsos_rpc_t *rpc, int server_num, sos_obj_t obj)
{
	assert(rpc->flags & DSOS_RPC_ALL);

	dsos_unpack_obj(&rpc->bufs[server_num].resp, obj);
}

void dsos_rpc_pack_obj(dsos_rpc_t *rpc, sos_obj_t obj)
{
	int	ret;

	assert(rpc->flags & DSOS_RPC_ONE);

	ret = dsos_pack_obj(&rpc->buf->req, obj);
	if (ret)
		dsos_err_set_local(rpc->status, rpc->server_num, E2BIG);
}

int dsos_rpc_pack_fits(dsos_rpc_t *rpc, int len)
{
	assert(rpc->flags & DSOS_RPC_ONE);

	return dsos_pack_fits(&rpc->buf->req, len);
}

int dsos_rpc_pack_obj_needs(sos_obj_t obj)
{
	return dsos_pack_obj_needs(obj);
}

void dsos_rpc_pack_schema_all(dsos_rpc_t *rpc, sos_schema_t schema)
{
	int	i, server_num;

	assert(rpc->flags & DSOS_RPC_ALL);

	for (i = 0; i < g.num_servers; ++i) {
		if (dsos_pack_schema(&rpc->bufs[i].req, schema)) {
			server_num = (rpc->flags & DSOS_RPC_ONE) ? rpc->server_num : i;
			dsos_err_set_local(rpc->status, i, E2BIG);
		}
	}
}

sos_schema_t dsos_rpc_unpack_schema_one(dsos_rpc_t *rpc, int server_num)
{
	assert(rpc->flags & DSOS_RPC_ALL);

	return dsos_unpack_schema(&rpc->bufs[server_num].resp);
}

void dsos_rpc_pack_key_one(dsos_rpc_t *rpc, sos_key_t key)
{
	int	ret;

	assert(rpc->flags & DSOS_RPC_ONE);

	ret = dsos_pack_key(&rpc->buf->req, key);
	if (ret)
		dsos_err_set_local(rpc->status, rpc->server_num, E2BIG);
}

void dsos_rpc_pack_key_all(dsos_rpc_t *rpc, sos_key_t key)
{
	int	i, server_num;

	assert(rpc->flags & DSOS_RPC_ALL);

	for (i = 0; i < g.num_servers; ++i) {
		if (dsos_pack_key(&rpc->bufs[i].req, key)) {
			server_num = (rpc->flags & DSOS_RPC_ONE) ? rpc->server_num : i;
			dsos_err_set_local(rpc->status, i, E2BIG);
		}
	}
}

void dsos_rpc_pack_attr_all(dsos_rpc_t *rpc, sos_attr_t attr)
{
	int	i, ret, server_num;

	assert(rpc->flags & DSOS_RPC_ALL);

	if (attr->schema->dsos.handles == NULL) {
		dsos_err_set_local_all(rpc->status, EINVAL);
		return;
	}

	for (i = 0; i < g.num_servers; ++i) {
		ret  = dsos_pack_handle(&rpc->bufs[i].req, attr->schema->dsos.handles[i]);
		ret |= dsos_pack_u32(&rpc->bufs[i].req, attr->data->id);
		if (ret) {
			server_num = (rpc->flags & DSOS_RPC_ONE) ? rpc->server_num : i;
			dsos_err_set_local(rpc->status, i, E2BIG);
		}
	}
}

void dsos_rpc_pack_value_all(dsos_rpc_t *rpc, sos_value_t value)
{
	int	i, ret, server_num;

	assert(rpc->flags & DSOS_RPC_ALL);

	if (value->attr->schema->dsos.handles == NULL) {
		dsos_err_set_local_all(rpc->status, EINVAL);
		return;
	}

	dsos_rpc_pack_attr_all(rpc, value->attr);

	for (i = 0; i < g.num_servers; ++i) {
		int	len  = sos_value_strlen(value) + 1;
		char	*str = dsos_malloc(len);
		sos_value_to_str(value, str, len);
		ret = dsos_pack_str(&rpc->bufs[i].req, str);
		if (ret) {
			server_num = (rpc->flags & DSOS_RPC_ONE) ? rpc->server_num : i;
			dsos_err_set_local(rpc->status, i, E2BIG);
		}
		free(str);
	}
}

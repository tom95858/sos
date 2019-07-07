/*
 * A DSOS RPC has the following attributes:
 *
 * 1. It contacts
 *    a. all servers, or
 *    c. one server;
 *
 * 2. It is
 *    a. synchronous, or
 *    b. asynchronous; and
 *
 * 3. It takes input and output parameters packaged as rpc_<rpcName>_in_t and
 *    rpc_<rpcName>_out_t structures and returns an int status.
 *
 * The RPC layer's job is to marshall the input parameters into one or
 * more request messages to be sent to one or all servers, send the
 * request(s), and either wait for the response(s) or return immediately.
 *
 * The request is sent using the dsos_req_* API which supports sending
 * to one server or to all servers.
 */

#include <string.h>
#include "dsos_priv.h"

static void rpc_set_status_cb(dsos_req_t *req, dsos_req_flags_t flags, dsos_buf_t *resp,
			      int server_num, void *ctxt)
{
	dsos_debug("req %p server %d resp %p/%d id %ld status %d\n", req, server_num,
		   resp->msg, resp->len, resp->msg->u.hdr.id, resp->msg->u.hdr.status);

	dsos_err_set_remote(req->status, server_num, resp->msg->u.hdr.status);
}

static void rpc_ping_cb(dsos_req_t *req, dsos_req_flags_t flags, dsos_buf_t *resp,
			int server_num, void *ctxt)
{
	rpc_ping_out_t	*args_outp = ctxt;

	args_outp->stats->tot_num_connects    = resp->msg->u.ping_resp.tot_num_connects;
	args_outp->stats->tot_num_disconnects = resp->msg->u.ping_resp.tot_num_disconnects;
	args_outp->stats->tot_num_reqs        = resp->msg->u.ping_resp.tot_num_reqs;
	args_outp->stats->num_clients         = resp->msg->u.ping_resp.num_clients;

	dsos_err_set_remote(req->status, server_num, resp->msg->u.hdr.status);
}

int dsos_rpc_ping_one(rpc_ping_in_t *args_inp, rpc_ping_out_t *args_outp)
{
	dsos_req_t	*req;

	args_outp->stats = args_inp->stats;

	req = dsos_req_new(DSOS_REQ_ONE, rpc_ping_cb, args_outp);

	req->buf->send.msg->u.hdr.type = DSOSD_MSG_PING_REQ;
	req->buf->send.len = sizeof(dsosd_msg_ping_req_t);

	dsos_req_set_server(req, args_inp->server_num);

	dsos_req_send(DSOS_REQ_WAIT | DSOS_REQ_CB, req);

	return dsos_err_status(dsos_errno);
}

static uint64_t nsecs_now()
{
	struct timespec	ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	return ts.tv_sec * 1.0e+9 + ts.tv_nsec;
}

static void rpc_ping_all_cb(dsos_req_t *req, dsos_req_flags_t flags, dsos_buf_t *resp,
			    int server_num, void *ctxt)
{
	dsosd_msg_ping_resp_t	*msg = (dsosd_msg_ping_resp_t *)resp->msg;
	rpc_ping_out_t		*args_outp = ctxt;

	args_outp->stats[server_num].tot_num_connects    = msg->tot_num_connects;
	args_outp->stats[server_num].tot_num_disconnects = msg->tot_num_disconnects;
	args_outp->stats[server_num].tot_num_reqs        = msg->tot_num_reqs;
	args_outp->stats[server_num].num_clients         = msg->num_clients;
	args_outp->stats[server_num].nsecs               = nsecs_now() - args_outp->stats[server_num].nsecs;

	dsos_err_set_remote(req->status, server_num, msg->hdr.status);
}

int dsos_rpc_ping_all(rpc_ping_in_t *args_inp, rpc_ping_out_t *args_outp)
{
	int		i;
	uint64_t	now;
	dsos_req_t	*req;

	args_outp->stats = (struct dsos_ping_stats *)malloc(sizeof(struct dsos_ping_stats) * g.num_servers);
	if (!args_outp->stats)
		dsos_fatal("out of memory\n");

	req = dsos_req_new(DSOS_REQ_ALL, rpc_ping_all_cb, args_outp);

	/* Copy in args to the request messages. */
	now = nsecs_now();
	for (i = 0; i < g.num_servers; ++i) {
		req->bufs[i].send.msg->u.hdr.type       = DSOSD_MSG_PING_REQ;
		req->bufs[i].send.msg->u.ping_req.debug = args_inp->debug;
		req->bufs[i].send.len                   = sizeof(dsosd_msg_ping_req_t);
		args_outp->stats[i].nsecs = now;
	}

	dsos_req_send(DSOS_REQ_WAIT | DSOS_REQ_CB_ALL, req);

	return dsos_err_status(dsos_errno);
}

int dsos_rpc_container_new(rpc_container_new_in_t  *args_inp,
			   rpc_container_new_out_t *args_outp)
{
	int				i;
	dsos_req_t			*req;
	dsosd_msg_container_new_req_t	*msg;
	dsosd_msg_container_new_resp_t	*resp;

	req = dsos_req_new(DSOS_REQ_ALL, rpc_set_status_cb, NULL);

	/* Copy in args to the request messages. */
	for (i = 0; i < g.num_servers; ++i) {
		msg = (dsosd_msg_container_new_req_t *)req->bufs[i].send.msg;
		msg->hdr.type = DSOSD_MSG_CONTAINER_NEW_REQ;
		strncpy(msg->path, args_inp->path, sizeof(msg->path));
		msg->mode = args_inp->mode;
		req->bufs[i].send.len = sizeof(dsosd_msg_container_new_req_t);
	}

	dsos_req_send(DSOS_REQ_WAIT | DSOS_REQ_CB_ALL, req);

	return dsos_err_status(dsos_errno);
}

static void rpc_container_open_cb(dsos_req_t *req, dsos_req_flags_t flags, dsos_buf_t *resp,
				  int server_num, void *ctxt)
{
	dsosd_msg_container_open_resp_t	*msg = (dsosd_msg_container_open_resp_t *)resp->msg;
	rpc_container_open_out_t	*args_outp = (rpc_container_open_out_t *)ctxt;

	dsos_debug("req %p server %d resp %p/%d id %ld status %d handle %p\n", req,
		   server_num, resp->msg, resp->len, msg->hdr.id, msg->hdr.status, msg->handle);

	args_outp->handles[server_num] = msg->handle;

	dsos_err_set_remote(req->status, server_num, msg->hdr.status);
}

int dsos_rpc_container_open(rpc_container_open_in_t  *args_inp,
			    rpc_container_open_out_t *args_outp)
{
	int				i;
	dsos_req_t			*req;
	dsosd_msg_container_open_req_t	*msg;
	dsos_buf_t			*buf;

	/* Allocate space for the output parms, filled in by the callback. Caller must free. */
	args_outp->handles = (dsosd_handle_t *)malloc(sizeof(dsosd_handle_t) * g.num_servers);
	if (!args_outp->handles)
		dsos_fatal("out of memory\n");

	req = dsos_req_new(DSOS_REQ_ALL, rpc_container_open_cb, args_outp);

	/* Copy in args to the request messages. */
	for (i = 0; i < g.num_servers; ++i) {
		msg = (dsosd_msg_container_open_req_t *)req->bufs[i].send.msg;
		msg->hdr.type = DSOSD_MSG_CONTAINER_OPEN_REQ;
		msg->perms    = args_inp->perms;
		strncpy(msg->path, args_inp->path, sizeof(msg->path));
		req->bufs[i].send.len = sizeof(dsosd_msg_container_open_req_t);
	}

	dsos_req_send(DSOS_REQ_WAIT | DSOS_REQ_CB_ALL, req);

	return dsos_err_status(dsos_errno);
}

int dsos_rpc_container_close(rpc_container_close_in_t  *args_inp,
			     rpc_container_close_out_t *args_outp)
{
	int				i;
	dsos_req_t			*req;
	dsosd_msg_container_close_req_t	*msg;

	req = dsos_req_new(DSOS_REQ_ALL, rpc_set_status_cb, NULL);

	/* Copy in args to the request messages. */
	for (i = 0; i < g.num_servers; ++i) {
		msg = (dsosd_msg_container_close_req_t *)req->bufs[i].send.msg;
		msg->hdr.type         = DSOSD_MSG_CONTAINER_CLOSE_REQ;
		msg->handle           = args_inp->handles[i];
		req->bufs[i].send.len = sizeof(dsosd_msg_container_close_req_t);
	}

	dsos_req_send(DSOS_REQ_WAIT | DSOS_REQ_CB_ALL, req);

	return dsos_err_status(dsos_errno);
}

static void rpc_schema_by_name_cb(dsos_req_t *req, dsos_req_flags_t flags, dsos_buf_t *resp,
				  int server_num, void *ctxt)
{
	dsosd_msg_schema_by_name_resp_t	*msg = (dsosd_msg_schema_by_name_resp_t *)resp->msg;
	rpc_schema_by_name_out_t	*args_outp = (rpc_schema_by_name_out_t *)ctxt;

	dsos_debug("req %p server %d resp %p/%d id %ld status %d handle %p\n", req,
		   server_num, resp->msg, resp->len, msg->hdr.id, msg->hdr.status, msg->handle);

	args_outp->handles[server_num] = msg->handle;
	memcpy(args_outp->templ, msg->templ, sizeof(args_outp->templ));

	dsos_err_set_remote(req->status, server_num, msg->hdr.status);
}

int dsos_rpc_schema_by_name(rpc_schema_by_name_in_t  *args_inp,
			    rpc_schema_by_name_out_t *args_outp)
{
	int				i;
	dsos_req_t			*req;
	dsosd_msg_schema_by_name_req_t	*msg;

	/* Copy out results from the responses. Caller must free. */
	args_outp->handles = (dsosd_handle_t *)malloc(sizeof(dsosd_handle_t) * g.num_servers);
	if (!args_outp->handles)
		dsos_fatal("out of memory\n");

	req = dsos_req_new(DSOS_REQ_ALL, rpc_schema_by_name_cb, args_outp);

	/* Copy in args to the request messages. */
	for (i = 0; i < g.num_servers; ++i) {
		msg = (dsosd_msg_schema_by_name_req_t *)req->bufs[i].send.msg;
		msg->hdr.type    = DSOSD_MSG_SCHEMA_BY_NAME_REQ;
		msg->cont_handle = args_inp->cont_handles[i];
		strncpy(msg->name, args_inp->name, sizeof(msg->name));
		req->bufs[i].send.len = sizeof(dsosd_msg_schema_by_name_req_t);
	}

	dsos_req_send(DSOS_REQ_WAIT | DSOS_REQ_CB_ALL, req);

	return dsos_err_status(dsos_errno);
}

static void rpc_schema_from_template_cb(dsos_req_t *req, dsos_req_flags_t flags, dsos_buf_t *resp,
					int server_num, void *ctxt)
{
	dsosd_msg_schema_from_template_resp_t	*msg = (dsosd_msg_schema_from_template_resp_t *)resp->msg;
	rpc_schema_from_template_out_t	*args_outp = (rpc_schema_from_template_out_t *)ctxt;

	dsos_debug("req %p server %d resp %p/%d id %ld status %d handle %p\n", req,
		   server_num, resp->msg, resp->len, msg->hdr.id, msg->hdr.status, msg->handle);

	args_outp->handles[server_num] = msg->handle;

	dsos_err_set_remote(req->status, server_num, msg->hdr.status);
}

int dsos_rpc_schema_from_template(rpc_schema_from_template_in_t  *args_inp,
				  rpc_schema_from_template_out_t *args_outp)
{
	int					i;
	dsos_req_t				*req;
	dsosd_msg_schema_from_template_req_t	*msg;

	args_outp->handles = (dsosd_handle_t *)malloc(sizeof(dsosd_handle_t) * g.num_servers);
	if (!args_outp->handles)
		dsos_fatal("out of memory\n");

	req = dsos_req_new(DSOS_REQ_ALL, rpc_schema_from_template_cb, args_outp);

	/* Copy in args to the request messages. */
	for (i = 0; i < g.num_servers; ++i) {
		msg = (dsosd_msg_schema_from_template_req_t *)req->bufs[i].send.msg;
		msg->hdr.type = DSOSD_MSG_SCHEMA_FROM_TEMPLATE_REQ;
		memcpy(msg->templ, args_inp->templ, args_inp->len);
		req->bufs[i].send.len = sizeof(dsosd_msg_schema_from_template_req_t);
	}

	dsos_req_send(DSOS_REQ_WAIT | DSOS_REQ_CB_ALL, req);

	return dsos_err_status(dsos_errno);
}

int dsos_rpc_schema_add(rpc_schema_add_in_t  *args_inp,
			rpc_schema_add_out_t *args_outp)
{
	int				i;
	dsos_req_t			*req;
	dsosd_msg_schema_add_req_t	*msg;

	req = dsos_req_new(DSOS_REQ_ALL, rpc_set_status_cb, NULL);

	/* Copy in args to the request messages. */
	for (i = 0; i < g.num_servers; ++i) {
		msg = (dsosd_msg_schema_add_req_t *)req->bufs[i].send.msg;
		msg->hdr.type         = DSOSD_MSG_SCHEMA_ADD_REQ;
		msg->cont_handle      = args_inp->cont_handles[i];
		msg->schema_handle    = args_inp->schema_handles[i];
		req->bufs[i].send.len = sizeof(dsosd_msg_schema_add_req_t);
	}

	dsos_req_send(DSOS_REQ_WAIT | DSOS_REQ_CB_ALL, req);

	return dsos_err_status(dsos_errno);
}

int dsos_rpc_part_create(rpc_part_create_in_t  *args_inp,
			 rpc_part_create_out_t *args_outp)
{
	int				i;
	dsos_req_t			*req;
	dsosd_msg_part_create_req_t	*msg;

	req = dsos_req_new(DSOS_REQ_ALL, rpc_set_status_cb, NULL);

	/* Copy in args to the request messages. */
	for (i = 0; i < g.num_servers; ++i) {
		msg = (dsosd_msg_part_create_req_t *)req->bufs[i].send.msg;
		msg->hdr.type    = DSOSD_MSG_PART_CREATE_REQ;
		msg->cont_handle = args_inp->cont_handles[i];
		strncpy(msg->name, args_inp->name, sizeof(msg->name));
		strncpy(msg->path, args_inp->path, sizeof(msg->path));
		req->bufs[i].send.len = sizeof(dsosd_msg_part_create_req_t);
	}

	dsos_req_send(DSOS_REQ_WAIT | DSOS_REQ_CB_ALL, req);

	return dsos_err_status(dsos_errno);
}

static void rpc_part_find_cb(dsos_req_t *req, dsos_req_flags_t flags, dsos_buf_t *resp,
			     int server_num, void *ctxt)
{
	dsosd_msg_part_find_resp_t	*msg = (dsosd_msg_part_find_resp_t *)resp->msg;
	rpc_part_find_out_t		*args_outp = (rpc_part_find_out_t *)ctxt;

	dsos_debug("req %p server %d resp %p/%d id %ld status %d handle %p\n", req,
		   server_num, resp->msg, resp->len, msg->hdr.id, msg->hdr.status, msg->handle);

	args_outp->handles[server_num] = msg->handle;

	dsos_err_set_remote(req->status, server_num, msg->hdr.status);
}

int dsos_rpc_part_find(rpc_part_find_in_t  *args_inp,
		       rpc_part_find_out_t *args_outp)
{
	int				i;
	dsos_req_t			*req;
	dsosd_msg_part_find_req_t	*msg;

	args_outp->handles = (dsosd_handle_t *)malloc(sizeof(dsosd_handle_t) * g.num_servers);
	if (!args_outp->handles)
		dsos_fatal("out of memory\n");

	req = dsos_req_new(DSOS_REQ_ALL, rpc_part_find_cb, args_outp);

	/* Copy in args to the request messages. */
	for (i = 0; i < g.num_servers; ++i) {
		msg = (dsosd_msg_part_find_req_t *)req->bufs[i].send.msg;
		msg->hdr.type         = DSOSD_MSG_PART_FIND_REQ;
		msg->cont_handle      = args_inp->cont_handles[i];
		strncpy(msg->name, args_inp->name, sizeof(msg->name));
		req->bufs[i].send.len = sizeof(dsosd_msg_part_find_req_t);
	}

	dsos_req_send(DSOS_REQ_WAIT | DSOS_REQ_CB_ALL, req);

	return dsos_err_status(dsos_errno);
}

int dsos_rpc_part_set_state(rpc_part_set_state_in_t  *args_inp,
			    rpc_part_set_state_out_t *args_outp)
{
	int				i;
	dsos_req_t			*req;
	dsosd_msg_part_set_state_req_t	*msg;

	req = dsos_req_new(DSOS_REQ_ALL, rpc_set_status_cb, NULL);

	/* Copy in args to the request messages. */
	for (i = 0; i < g.num_servers; ++i) {
		msg = (dsosd_msg_part_set_state_req_t *)req->bufs[i].send.msg;
		msg->hdr.type         = DSOSD_MSG_PART_SET_STATE_REQ;
		msg->handle           = args_inp->handles[i];
		msg->new_state        = args_inp->new_state;
		req->bufs[i].send.len = sizeof(dsosd_msg_part_set_state_req_t);
	}

	dsos_req_send(DSOS_REQ_WAIT | DSOS_REQ_CB_ALL, req);

	return dsos_err_status(dsos_errno);
}

static void obj_create_cb(dsos_req_t *req, dsos_req_flags_t flags, dsos_buf_t *resp,
			  int server_num, void *ctxt)
{
	sos_obj_t	obj = ctxt;
	dsos_obj_cb_t	cb  = req->ctxt2.ptr1;

	dsos_debug("obj %p len %d from server %d req %p cb %p/%p obj_id %08lx%08lx\n",
		   obj, resp->len, server_num, req, req->ctxt2.ptr1, req->ctxt2.ptr2,
		   resp->msg->u.hdr2.obj_id.as_ref.ref.ods, resp->msg->u.hdr2.obj_id.as_ref.ref.obj);

	obj->obj_ref.ref = resp->msg->u.hdr2.obj_id.as_ref.ref;
	cb(obj, req->ctxt2.ptr2);

	/* Drop the ref taken in dsos_obj_create(). */
	sos_obj_put(obj);
}

// This call is asynchronous.
int dsos_rpc_object_create(rpc_object_create_in_t *args_inp)
{
	int				server_id;
	char				*obj_data;
	size_t				obj_sz, req_len;
	dsos_req_t			*req;
	dsosd_msg_obj_create_req_t	*msg;
	uint8_t				sha[SHA256_DIGEST_LENGTH];

	req = dsos_req_new(DSOS_REQ_ONE, obj_create_cb, args_inp->obj);
	req->ctxt2.ptr1 = args_inp->cb;
	req->ctxt2.ptr2 = args_inp->ctxt;

	/* Calculate the owning DSOS server. */
	sos_obj_data_get(args_inp->obj, &obj_data, &obj_sz);
	SHA256(obj_data, obj_sz, sha);
	server_id = sha[0] % g.num_servers;

	/*
	 * Copy in args to the request message. If the object fits into
	 * the message, copy it and send it in-line.
	 */
	msg = (dsosd_msg_obj_create_req_t *)req->buf->send.msg;
	msg->hdr.type      = DSOSD_MSG_OBJ_CREATE_REQ;
	msg->hdr2.obj_sz   = obj_sz;
	msg->schema_handle = args_inp->schema->handles[server_id];

	if (obj_sz > (req->buf->send.max_len - sizeof(dsosd_msg_obj_create_req_t))) {
		msg->hdr2.obj_va = (uint64_t)obj_data;
		req_len = sizeof(dsosd_msg_obj_create_req_t);
	} else {
		msg->hdr2.obj_va = 0;
		msg->hdr.flags |= DSOSD_MSG_IMM;
		memcpy(msg->data, obj_data, obj_sz);
		req_len = sizeof(dsosd_msg_obj_create_req_t) + obj_sz;
	}
	req->buf->send.len = req_len;

	dsos_debug("obj %p schema %p obj_data %p obj_sz %d%s owned by server %d\n",
		   args_inp->obj, msg->schema_handle, obj_data, obj_sz,
		   msg->hdr.flags & DSOSD_MSG_IMM ? " inline" : "", server_id);

	/* This can block until resources (SQ or RQ credits) are available. */
	dsos_req_set_server(req, server_id);
	return dsos_req_send(DSOS_REQ_CB, req);
}

int dsos_rpc_object_delete(rpc_object_delete_in_t *args_inp,
			   rpc_object_delete_out_t *args_outp)
{
	int		ret, server_num;
	dsos_req_t	*req;
	dsos_schema_t	*schema;

	req = dsos_req_new(DSOS_REQ_ONE, rpc_set_status_cb, NULL);

	schema     = (dsos_schema_t *)args_inp->obj->ctxt;
	server_num = dsos_obj_server(args_inp->obj);

	dsos_debug("obj %p %08lx%08lx\n", args_inp->obj,
		   args_inp->obj->obj_ref.ref.ods, args_inp->obj->obj_ref.ref.obj);

	req->buf->send.msg->u.hdr.type                   = DSOSD_MSG_OBJ_DELETE_REQ;
	req->buf->send.msg->u.hdr2.obj_id.as_ref         = args_inp->obj->obj_ref;
	req->buf->send.msg->u.obj_delete_req.cont_handle = schema->cont->handles[server_num];
	req->buf->send.len = sizeof(dsosd_msg_obj_delete_req_t);

	dsos_req_set_server(req, server_num);

	dsos_req_send(DSOS_REQ_WAIT | DSOS_REQ_CB, req);

	return dsos_err_status(dsos_errno);
}

static char *serialize_uint32(const int v, char **pp, size_t *psz)
{
	char	*ret = *pp;
	size_t	len = sizeof(uint32_t);

	if (len <= *psz) {
		*(uint32_t *)*pp = v;
		*pp  += len;
		*psz -= len;
		return ret;
	} else {
		*psz = -1;
		return NULL;
	}
}

static char *serialize_str(const char *v, char **pp, size_t *psz)
{
	char	*ret = *pp;
	size_t	len;

	len = 1;  // include NULL terminating byte
	if (v)
		len += strlen(v);
	if (len <= *psz) {
		if (v)
			strncpy(*pp, v, len);  // strncpy will write the terminating NULL
		else
			**pp = 0;
		*pp  += len;
		*psz -= len;
		return ret;
	} else {
		*psz = -1;
		return NULL;
	}
}

static char *serialize_buf(const void *v, size_t len, char **pp, size_t *psz)
{
	char	*ret = *pp;

	if (len <= *psz) {
		memcpy(*pp, v, len);
		*pp  += len;
		*psz -= len;
		return ret;
	} else {
		*psz = -1;
		return NULL;
	}
}

static uint32_t deserialize_uint32(char **pbuf, size_t *psz)
{
	uint32_t	ret = *(uint32_t *)*pbuf;
	size_t		len = sizeof(uint32_t);

	*pbuf += len;
	*psz  -= len;
	return ret;
}

static char *deserialize_str(char **pbuf, size_t *psz)
{
	char		*ret = *pbuf;
	size_t		len = strlen(ret) + 1;

	if (len == 1)
		ret = NULL;
	*pbuf += len;
	*psz  -= len;
	return ret;
}

void *dsos_rpc_serialize_schema_template(sos_schema_template_t t, void *buf, size_t *psz)
{
	int		i, j;
	uint32_t	*p_attrs_len, *p_joinlist_len;
	char		*p = buf;

	serialize_str(t->name, &p, psz);
	p_attrs_len = (uint32_t *)serialize_uint32(0, &p, psz);
	for (i = 0; t->attrs[i].name; ++i) {
		serialize_str   (t->attrs[i].name, &p, psz);
		serialize_uint32(t->attrs[i].type, &p, psz);
		serialize_uint32(t->attrs[i].size, &p, psz);
		p_joinlist_len = (uint32_t *)serialize_uint32(0, &p, psz);
		if (t->attrs[i].join_list) {
			for (j = 0; j < t->attrs[i].size; ++j)
				serialize_str(t->attrs[i].join_list[j], &p, psz);
			if (*psz >= 0) *p_joinlist_len = j;
		}
		serialize_uint32(t->attrs[i].indexed,  &p, psz);
		serialize_str   (t->attrs[i].idx_type, &p, psz);
		serialize_str   (t->attrs[i].key_type, &p, psz);
		serialize_str   (t->attrs[i].idx_args, &p, psz);
	}
	if (*psz >= 0) {
		*p_attrs_len = i;
		*psz = p - (char *)buf;
		return buf;
	} else {
		return NULL;
	}
}

// Serialize as byte_count (32 bits) followed by attr_data.
void *dsos_rpc_serialize_attr_value(sos_value_t v, void *buf, size_t *psz)
{
	size_t	sz = sos_value_size(v);

	serialize_uint32(sz, buf, psz);

	if (sos_value_is_array(v))
		return serialize_buf(&v->data->array.data, sz, buf, psz);
	else
		return serialize_buf(&v->data->prim, sz, buf, psz);
}

sos_schema_template_t dsos_rpc_deserialize_schema_template(char *buf, size_t len)
{
	int			i, j;
	char			*name;
	uint32_t		num_attrs, num_join_attrs;
	sos_schema_template_t	t;

	name      = deserialize_str(&buf, &len);
	num_attrs = deserialize_uint32(&buf, &len);

	t = (sos_schema_template_t)malloc(sizeof(struct sos_schema_template) +
					  sizeof(struct sos_schema_template_attr) * (num_attrs+1));
	if (!t)
		return NULL;

	t->name = name;
	for (i = 0; i < num_attrs; ++i) {
		t->attrs[i].name = deserialize_str   (&buf, &len);
		t->attrs[i].type = deserialize_uint32(&buf, &len);
		t->attrs[i].size = deserialize_uint32(&buf, &len);
		num_join_attrs   = deserialize_uint32(&buf, &len);
		t->attrs[i].join_list = NULL;
		if (num_join_attrs) {
			t->attrs[i].join_list = malloc(sizeof(char *) * num_join_attrs);
			for (j = 0; j < num_join_attrs; ++j)
				t->attrs[i].join_list[j] = deserialize_str(&buf, &len);
		}
		t->attrs[i].indexed  = deserialize_uint32(&buf, &len);
		t->attrs[i].idx_type = deserialize_str   (&buf, &len);
		t->attrs[i].key_type = deserialize_str   (&buf, &len);
		t->attrs[i].idx_args = deserialize_str   (&buf, &len);
	}
	t->attrs[i].name = NULL;

	return t;
}

void dsos_rpc_free_schema_template(sos_schema_template_t t)
{
	int	i;

	for (i = 0; t->attrs[i].name; ++i) {
		if (t->attrs[i].join_list)
			free(t->attrs[i].join_list);
	}
	free(t);
}

static void rpc_obj_get_cb(dsos_req_t *req, dsos_req_flags_t flags, dsos_buf_t *resp,
			   int server_num, void *ctxt)
{
	size_t				obj_sz;
	char				*obj_data;
	sos_obj_t			obj = (sos_obj_t)ctxt;
	dsosd_msg_obj_get_resp_t	*msg = (dsosd_msg_obj_get_resp_t *)resp->msg;

	if (msg->hdr.flags & DSOSD_MSG_IMM) {
		sos_obj_data_get(obj, &obj_data, &obj_sz);
		memcpy(obj_data, msg->data, msg->hdr2.obj_sz);
		dsos_debug("req %p len %d copied to obj_data %p\n", req, resp->len, obj_data);
	} else {
		dsos_debug("req %p len %d flushed\n", req, resp->len);
	}
	obj->obj_ref.ref = msg->hdr2.obj_id.as_ref.ref;

	dsos_err_set_remote(req->status, server_num, msg->hdr.status);
}

int dsos_rpc_obj_get(rpc_obj_get_in_t *args_inp, rpc_obj_get_out_t *args_outp)
{
	int			server_num;
	size_t			obj_sz;
	char			*obj_data;
	dsos_req_t		*req;
	dsosd_msg_obj_get_req_t	*msg;

	req = dsos_req_new(DSOS_REQ_ONE, rpc_obj_get_cb, args_inp->sos_obj);

	server_num = dsos_obj_server(args_inp->sos_obj);
	sos_obj_data_get(args_inp->sos_obj, &obj_data, &obj_sz);

	msg = (dsosd_msg_obj_get_req_t *)req->buf->send.msg;
	msg->hdr.type          = DSOSD_MSG_OBJ_GET_REQ;
	msg->cont_handle       = args_inp->cont->handles[server_num];
	msg->obj_id.as_ref     = args_inp->obj_id;
	msg->hdr2.obj_va       = (uint64_t)obj_data;
	msg->hdr2.obj_sz       = obj_sz;
	req->buf->send.len     = sizeof(dsosd_msg_obj_get_req_t);

	dsos_req_set_server(req, server_num);
	dsos_req_send(DSOS_REQ_WAIT | DSOS_REQ_CB, req);

	dsos_debug("obj_id %08lx%08lx flags %x sos_obj %p status %d\n",
		   args_inp->obj_id.ref.ods, args_inp->obj_id.ref.obj,
		   req->buf->resp.msg->u.hdr.flags, args_inp->sos_obj,
		   dsos_err_status(dsos_errno));

	return dsos_err_status(dsos_errno);
}

static void rpc_iter_new_cb(dsos_req_t *req, dsos_req_flags_t flags, dsos_buf_t *resp,
			    int server_num, void *ctxt)
{
	dsosd_msg_iterator_new_resp_t	*msg = (dsosd_msg_iterator_new_resp_t *)resp->msg;
	rpc_iter_new_out_t		*args_outp = (rpc_iter_new_out_t *)ctxt;

	dsos_debug("req %p server %d resp %p/%d id %ld status %d handle %p\n", req,
		   server_num, resp->msg, resp->len, msg->hdr.id, msg->hdr.status, msg->iter_handle);

	args_outp->handles[server_num] = msg->iter_handle;

	dsos_err_set_remote(req->status, server_num, msg->hdr.status);
}

int dsos_rpc_iter_new(rpc_iter_new_in_t *args_inp, rpc_iter_new_out_t *args_outp)
{
	int				i;
	dsos_req_t			*req;
	dsosd_msg_iterator_new_req_t	*msg;

	args_outp->handles = (dsosd_handle_t *)malloc(sizeof(dsosd_handle_t) * g.num_servers);
	if (!args_outp->handles)
		dsos_fatal("out of memory\n");

	req = dsos_req_new(DSOS_REQ_ALL, rpc_iter_new_cb, args_outp);

	/* Copy in args to the request messages. */
	for (i = 0; i < g.num_servers; ++i) {
		msg = (dsosd_msg_iterator_new_req_t *)req->bufs[i].send.msg;
		msg->hdr.type          = DSOSD_MSG_ITERATOR_NEW_REQ;
		msg->schema_handle     = args_inp->schema_handles[i];
		msg->attr_id           = sos_attr_id(args_inp->attr);
		req->bufs[i].send.len  = sizeof(dsosd_msg_iterator_new_req_t);
	}

	dsos_req_send(DSOS_REQ_WAIT | DSOS_REQ_CB_ALL, req);

	return dsos_err_status(dsos_errno);
}

int dsos_rpc_iter_close(rpc_iter_close_in_t *args_inp, rpc_iter_close_out_t *args_outp)
{
	int				i;
	dsos_req_t			*req;
	dsosd_msg_iterator_close_req_t	*msg;

	req = dsos_req_new(DSOS_REQ_ALL, rpc_set_status_cb, NULL);

	/* Copy in args to the request messages. */
	for (i = 0; i < g.num_servers; ++i) {
		msg = (dsosd_msg_iterator_close_req_t *)req->bufs[i].send.msg;
		msg->hdr.type          = DSOSD_MSG_ITERATOR_CLOSE_REQ;
		msg->iter_handle       = args_inp->iter_handles[i];
		req->bufs[i].send.len  = sizeof(dsosd_msg_iterator_close_req_t);
	}

	dsos_req_send(DSOS_REQ_WAIT | DSOS_REQ_CB_ALL, req);

	return dsos_err_status(dsos_errno);
}

static void rpc_step_all_cb(dsos_req_t *req, dsos_req_flags_t flags, dsos_buf_t *resp,
			    int server_num, void *ctxt)
{
	char				*obj_data;
	size_t				obj_sz;
	dsosd_msg_iterator_step_resp_t	*msg = (dsosd_msg_iterator_step_resp_t *)resp->msg;
	rpc_iter_step_all_in_t		*args_inp  = (rpc_iter_step_all_in_t  *)req->ctxt2.ptr1;
	rpc_iter_step_all_out_t		*args_outp = (rpc_iter_step_all_out_t *)req->ctxt2.ptr2;

	switch (msg->hdr.status) {
	    case 0:
		args_outp->found[server_num] = 1;
		if (msg->hdr.flags & DSOSD_MSG_IMM) {
			sos_obj_data_get(args_inp->sos_objs[server_num], &obj_data, &obj_sz);
			memcpy(obj_data, msg->data, obj_sz);
			dsos_debug("obj len %d from server %d inline\n", obj_sz, server_num);
		} else {
			dsos_debug("obj len %d from server %d\n", msg->hdr2.obj_sz, server_num);
		}
		args_inp->sos_objs[server_num]->obj_ref.ref = msg->hdr2.obj_id.as_ref.ref;
		break;
	    case ENOENT:
		args_outp->found[server_num] = 0;
		break;
	    default:
		args_outp->found[server_num] = 0;
		dsos_error("err %d from server %d\n", msg->hdr.status, server_num);
		dsos_err_set_remote(req->status, server_num, msg->hdr.status);
		break;
	}
}

int dsos_rpc_iter_step_all(rpc_iter_step_all_in_t *args_inp, rpc_iter_step_all_out_t *args_outp)
{
	int				i;
	size_t				buf_len, key_sz, obj_sz;
	char				*buf, *obj_data, *p;
	void				*key_data;
	dsos_req_t			*req;
	dsosd_msg_iterator_step_req_t	*msg;
	dsos_ptr_tuple_t		ctxt;

	dsos_debug("op %d\n", args_inp->op);

	args_outp->found = (int *)malloc(g.num_servers * sizeof(int));
	if (!args_outp->found)
		return ENOMEM;

	req = dsos_req_new(DSOS_REQ_ALL, rpc_step_all_cb, NULL);
	req->ctxt2.ptr1 = args_inp;
	req->ctxt2.ptr2 = args_outp;

	/* Copy in args to the request messages. */
	if (args_inp->key) {
		key_sz   = sos_key_len(args_inp->key);
		key_data = sos_key_value(args_inp->key);
	}
	for (i = 0; i < g.num_servers; ++i) {
		sos_obj_data_get(args_inp->sos_objs[i], &obj_data, &obj_sz);
		msg = (dsosd_msg_iterator_step_req_t *)req->bufs[i].send.msg;
		msg->hdr.type    = DSOSD_MSG_ITERATOR_STEP_REQ;
		msg->op          = args_inp->op;
		msg->iter_handle = args_inp->iter_handles[i];
		msg->hdr2.obj_va = (uint64_t)obj_data;
		msg->hdr2.obj_sz = obj_sz;
		if (args_inp->key) {
			// buf_len is what's available in the serialization buffer
			buf_len = req->bufs[i].send.max_len - sizeof(dsosd_msg_iterator_step_req_t);
			buf = msg->data;
			serialize_uint32(key_sz, &buf, &buf_len);
			// XXX need check for buf too small (serialize_buf returns NULL)
			serialize_buf(key_data, key_sz, &buf, &buf_len);
			msg->data_len = buf - msg->data;
		} else {
			msg->data_len = 0;
		}
		req->bufs[i].send.len = sizeof(dsosd_msg_iterator_step_req_t) + msg->data_len;
	}

	dsos_req_send(DSOS_REQ_WAIT | DSOS_REQ_CB_ALL, req);

	return dsos_err_status(dsos_errno);
}

static void rpc_step_one_cb(dsos_req_t *req, dsos_req_flags_t flags, dsos_buf_t *resp,
			    int server_num, void *ctxt)
{
	size_t				obj_sz;
	char				*obj_data;
	dsosd_msg_iterator_step_resp_t	*msg = (dsosd_msg_iterator_step_resp_t *)resp->msg;
	dsos_ptr_tuple_t		*args = (dsos_ptr_tuple_t *)ctxt;
	rpc_iter_step_one_in_t		*args_inp  = args->ptr1;
	rpc_iter_step_one_out_t		*args_outp = args->ptr2;

	switch (msg->hdr.status) {
	    case 0:
		args_outp->found = 1;
		if (msg->hdr.flags & DSOSD_MSG_IMM) {
			sos_obj_data_get(args_inp->sos_obj, &obj_data, &obj_sz);
			memcpy(obj_data, msg->data, obj_sz);
			dsos_debug("obj len %d from server %d inline\n", obj_sz, server_num);
		} else {
			dsos_debug("obj len %d from server %d\n", obj_sz, server_num);
		}
		args_inp->sos_obj->obj_ref.ref = msg->hdr2.obj_id.as_ref.ref;
		break;
	    case ENOENT:
		args_outp->found = 0;
		break;
	    default:
		args_outp->found  = 0;
		dsos_error("err %d from server %d\n", msg->hdr.status, server_num);
		dsos_err_set_remote(req->status, server_num, msg->hdr.status);
		break;
	}
}

int dsos_rpc_iter_step_one(rpc_iter_step_one_in_t *args_inp, rpc_iter_step_one_out_t *args_outp)
{
	int				ret;
	size_t				obj_sz;
	char				*obj_data;
	dsos_req_t			*req;
	dsosd_msg_iterator_step_req_t	*msg;
	dsos_ptr_tuple_t		ctxt;

	ctxt.ptr1 = args_inp;
	ctxt.ptr2 = args_outp;
	req = dsos_req_new(DSOS_REQ_ALL, rpc_step_one_cb, &ctxt);

	sos_obj_data_get(args_inp->sos_obj, &obj_data, &obj_sz);

	/* Copy in args to the request message. */
	msg = (dsosd_msg_iterator_step_req_t *)req->buf->send.msg;
	msg->hdr.type      = DSOSD_MSG_ITERATOR_STEP_REQ;
	msg->op            = args_inp->op;
	msg->iter_handle   = args_inp->iter_handle;
	msg->data_len      = 0;
	msg->hdr2.obj_va   = (uint64_t)obj_data;
	msg->hdr2.obj_sz   = obj_sz;
	req->buf->send.len = sizeof(dsosd_msg_iterator_step_req_t);

	dsos_req_set_server(req, args_inp->server_num);

	dsos_req_send(DSOS_REQ_WAIT | DSOS_REQ_CB, req);

	return dsos_err_status(dsos_errno);
}

static void rpc_step_one_async_cb(dsos_req_t *req, dsos_req_flags_t flags, dsos_buf_t *resp,
				  int server_num, void *ctxt)
{
	size_t				obj_sz;
	char				*obj_data;
	dsosd_msg_iterator_step_resp_t	*msg  = (dsosd_msg_iterator_step_resp_t *)resp->msg;
	sos_obj_t			obj   = ctxt;
	dsos_req_cb2_t			cb    = req->ctxt2.ptr1;
	dsos_iter_t			*iter = req->ctxt2.ptr2;

	switch (msg->hdr.status) {
	    case 0:
		if (msg->hdr.flags & DSOSD_MSG_IMM) {
			sos_obj_data_get(obj, &obj_data, &obj_sz);
			memcpy(obj_data, msg->data, obj_sz);
			dsos_debug("obj %p len %d from server %d inline\n", obj, obj_sz, server_num);
		} else {
			dsos_debug("obj %p len %d from server %d\n", obj, msg->hdr2.obj_sz, server_num);
		}
		obj->obj_ref.ref = msg->hdr2.obj_id.as_ref.ref;
		break;
	    case ENOENT:
		dsos_debug("no obj from server %d\n", server_num);
		break;
	    default:
		dsos_error("err %d from server %d\n", msg->hdr.status, server_num);
		dsos_err_set_remote(req->status, server_num, msg->hdr.status);
		break;
	}
	/*
	 * Call the iterator callback. This is only to avoid mixing
	 * RPC- and API-layer abstractions.
	 */
	cb(req, flags, iter, obj);
}

dsos_req_t *dsos_rpc_iter_step_one_async(rpc_iter_step_one_in_t *args_inp)
{
	int				ret;
	size_t				obj_sz;
	char				*obj_data;
	dsos_req_t			*req;
	dsosd_msg_iterator_step_req_t	*msg;

	req = dsos_req_new(DSOS_REQ_ONE, rpc_step_one_async_cb, args_inp->sos_obj);
	req->ctxt2.ptr1 = args_inp->cb;
	req->ctxt2.ptr2 = args_inp->iter;

	sos_obj_data_get(args_inp->sos_obj, &obj_data, &obj_sz);

	/* Copy in args to the request message. */
	msg = (dsosd_msg_iterator_step_req_t *)req->buf->send.msg;
	msg->hdr.type      = DSOSD_MSG_ITERATOR_STEP_REQ;
	msg->op            = args_inp->op;
	msg->iter_handle   = args_inp->iter_handle;
	msg->data_len      = 0;
	msg->hdr2.obj_va   = (uint64_t)obj_data;
	msg->hdr2.obj_sz   = obj_sz;
	req->buf->send.len = sizeof(dsosd_msg_iterator_step_req_t);

	dsos_req_set_server(req, args_inp->server_num);

	ret = dsos_req_send(DSOS_REQ_CB, req);
	if (ret)
		return NULL;
	return req;
}

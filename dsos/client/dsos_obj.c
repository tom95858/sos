#include "dsos_priv.h"

static void	obj_create_cb(dsos_req_t *req, size_t len, void *ctxt);

dsos_obj_t *dsos_obj_alloc(size_t sz, dsos_obj_cb_t cb, void *ctxt)
{
	size_t				max_inline;
	void				*buf;
	dsos_obj_t			*obj;
	dsos_req_t			*req;
	dsosd_msg_obj_create_req_t	*msg;

	obj = malloc(sizeof(dsos_obj_t));
	if (!obj)
		return NULL;

	req = dsos_req_new(obj_create_cb, obj);
	if (!req)
		return NULL;

	msg = (dsosd_msg_obj_create_req_t *)req->msg;
	msg->hdr.type   = DSOSD_MSG_OBJ_CREATE_REQ;
	msg->hdr.flags  = 0;
	msg->hdr.status = 0;

	obj->flags = 0;
	max_inline = req->msg_len_max - sizeof(dsosd_msg_obj_create_req_t);
	if (sz > max_inline) {
		// alloc from client/server shared heap
		buf = mm_alloc(g.heap, sz);
		if (!buf)
			return NULL;
		msg->va = (uint64_t)buf;
		obj->max_sz = sz;
	} else {
		// alloc in-line (within the send buffer)
		msg->hdr.flags |= DSOSD_MSG_IMM;
		obj->flags |= DSOS_OBJ_INLINE;
		buf = msg->data;
		msg->va = 0;
		obj->max_sz = max_inline;
	}
	obj->buf  = buf;
	obj->req  = req;
	obj->cb   = cb;
	obj->ctxt = ctxt;

	dsos_debug("obj %p req %p msg %p buf %p\n", obj, req, msg, buf);

	return obj;
}

void dsos_obj_free(dsos_obj_t *obj)
{
	dsos_debug("obj %p req %p flags 0x%x msg %p buf %p\n", obj, obj->req, obj->flags, obj->req->msg, obj->buf);

	if (!(obj->flags & DSOS_OBJ_INLINE))
		mm_free(g.heap, obj->buf);
	free(obj);
}

int dsos_obj_create(dsos_obj_t *obj, dsos_schema_t *schema, size_t len)
{
	int			ret;
	rpc_object_create_in_t	args_in;

	obj->actual_sz = len;

	args_in.obj    = obj;
	args_in.schema = schema;
	args_in.len    = len;

	ret = dsos_rpc_object_create(&args_in);

	dsos_debug("obj %p schema %p len %d rpc %d\n", obj, schema, len, ret);
	return ret;
}

static void obj_create_cb(dsos_req_t *req, size_t len, void *ctxt)
{
	dsos_obj_t	*obj  = ctxt;
	dsos_conn_t	*conn = req->conn;

	// req->resp contains the response (status, global obj id)

	dsos_debug("obj %p req %p conn %p len %d buf %p\n", obj, req, conn, len, obj->buf);
	if (obj->cb)
		obj->cb(obj, obj->ctxt);
	dsos_obj_free(obj);
	dsos_req_put(req);
}

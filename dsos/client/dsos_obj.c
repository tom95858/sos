#include "dsos_priv.h"

static void	obj_create_cb(dsos_req_t *req, size_t len, void *ctxt);

dsos_obj_t *dsos_obj_alloc(dsos_schema_t *schema, dsos_obj_cb_t cb, void *ctxt)
{
	dsos_obj_t			*obj;
	dsos_req_t			*req;
	dsosd_msg_obj_create_req_t	*msg;

	obj = malloc(sizeof(dsos_obj_t));
	if (!obj)
		return NULL;

	req = dsos_req_new(obj_create_cb, obj);
	if (!req)
		return NULL;
	dsos_req_get(req);

	msg = (dsosd_msg_obj_create_req_t *)req->msg;
	msg->hdr.type   = DSOSD_MSG_OBJ_CREATE_REQ;
	msg->hdr.flags  = 0;
	msg->hdr.status = 0;

	obj->flags   = 0;
	obj->req_all = NULL;
	obj->req     = req;
	obj->cb      = cb;
	obj->ctxt    = ctxt;
	obj->schema  = schema;
	obj->sos_obj = sos_obj_malloc(schema->sos_schema);
	if (!obj->sos_obj) {
		dsos_error("could not create obj schema %p\n", schema);
		return NULL;
	}

	dsos_debug("obj %p req %p msg %p cb %p/%p\n", obj, req, msg, cb, ctxt);

	return obj;
}

void dsos_obj_free(dsos_obj_t *obj)
{
	dsos_debug("obj %p sos_obj %p req %p req_all %p flags 0x%x msg %p buf %p\n",
		   obj, obj->sos_obj, obj->req, obj->req_all, obj->flags,
		   obj->req->msg, obj->buf);

	if (!(obj->flags & DSOS_OBJ_INLINE))
		mm_free(g.heap, obj->buf);
	sos_obj_put(obj->sos_obj);
	dsos_req_put(obj->req);
	if (obj->req_all)
		dsos_req_all_put(obj->req_all);
	free(obj);
}

int dsos_obj_create(dsos_obj_t *obj)
{
	int				ret;
	char				*obj_data;
	size_t				max_inline, obj_sz;
	rpc_object_create_in_t		args_in;
	dsos_req_t			*req = obj->req;
	dsosd_msg_obj_create_req_t	*msg = (dsosd_msg_obj_create_req_t *)req->msg;

	sos_obj_data_get(obj->sos_obj, &obj_data, &obj_sz);

	max_inline = req->msg_len_max - sizeof(dsosd_msg_obj_create_req_t);
	if (obj_sz > max_inline) {
		// alloc from client/server shared heap
		obj->buf = mm_alloc(g.heap, obj_sz);
		if (!obj->buf)
			return ENOMEM;
		msg->va = (uint64_t)obj->buf;
	} else {
		// alloc in-line (within the send buffer)
		msg->hdr.flags |= DSOSD_MSG_IMM;
		obj->flags |= DSOS_OBJ_INLINE;
		obj->buf = msg->data;
		msg->va = 0;
	}

	memcpy(obj->buf, obj_data, obj_sz);

	args_in.obj = obj;

	ret = dsos_rpc_object_create(&args_in);

	dsos_debug("obj %p schema %p obj_data %p sz %d req %p buf %p cb %p/%p rpc %d\n", obj, obj->schema,
		   obj_data, obj_sz, obj->req, obj->buf, obj->cb, obj->ctxt, ret);
	return ret;
}

static void obj_create_cb(dsos_req_t *req, size_t len, void *ctxt)
{
	dsos_obj_t			*obj  = ctxt;
	dsos_conn_t			*conn = req->conn;
	dsosd_msg_obj_create_resp_t	*resp = (dsosd_msg_obj_create_resp_t *)obj->req->resp;

	// req->resp contains the response (status, global obj id)

	dsos_debug("obj %p flags 0x%x req %p conn %p len %d buf %p cb %p/%p\n",
		   obj, obj->flags, req, conn, len, obj->buf, obj->cb, obj->ctxt);

	obj->flags |= DSOS_OBJ_CREATED;
	obj->obj_id = resp->obj_id;
	if (obj->cb)
		obj->cb(obj, obj->ctxt);
	dsos_req_put(req);
}

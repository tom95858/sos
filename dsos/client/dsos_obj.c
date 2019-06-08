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
	obj->refcount = 1;  // this ref must be put by the application

	req = dsos_req_new(obj_create_cb, obj);
	if (!req)
		return NULL;

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

void dsos_obj_get(dsos_obj_t *obj)
{
	ods_atomic_inc(&obj->refcount);
}

void dsos_obj_put(dsos_obj_t *obj)
{
	dsos_debug("obj %p sos_obj %p req %p req_all %p flags 0x%x msg %p\n",
		   obj, obj->sos_obj, obj->req, obj->req_all, obj->flags,
		   obj->req->msg);

	if (!ods_atomic_dec(&obj->refcount)) {
		sos_obj_put(obj->sos_obj);
		dsos_req_put(obj->req);
		if (obj->req_all)
			dsos_req_all_put(obj->req_all);
		free(obj);
	}
}

int dsos_obj_create(dsos_obj_t *obj)
{
	rpc_object_create_in_t	args_in;

	args_in.obj = obj;

	dsos_obj_get(obj);  // this is put in the obj_create_cb() below

	return dsos_rpc_object_create(&args_in);
}

static void obj_create_cb(dsos_req_t *req, size_t len, void *ctxt)
{
	dsos_obj_t			*obj  = ctxt;
	dsos_conn_t			*conn = req->conn;
	dsosd_msg_obj_create_resp_t	*resp = (dsosd_msg_obj_create_resp_t *)obj->req->resp;

	// req->resp contains the response (status, global obj id)

	dsos_debug("obj %p flags 0x%x req %p conn %p len %d cb %p/%p\n",
		   obj, obj->flags, req, conn, len, obj->cb, obj->ctxt);

	obj->flags |= DSOS_OBJ_CREATED;
	obj->obj_id = resp->obj_id;
	if (obj->cb)
		obj->cb(obj, obj->ctxt);
	dsos_obj_put(obj);
}

static int attr_value_to_server(sos_value_t v)
{
	uint8_t		sha[SHA256_DIGEST_LENGTH];
	size_t		sz = sos_value_size(v);

	if (sos_value_is_array(v))
		SHA256((const unsigned char *)&v->data->array.data, sz, sha);
	else
		SHA256((const unsigned char *)&v->data->prim, sz, sha);

	return sha[0] % g.num_servers;
}

int dsos_obj_index(dsos_obj_t *obj, dsos_obj_cb_t cb, void *ctxt)
{
	int			i, ret, server_num;
	size_t			len;
	sos_attr_t		attr;
	sos_value_t		v;
	sos_schema_t		schema;
	dsos_req_t		**reqs;
	rpc_obj_index_in_t	*args_in;

	dsos_debug("obj %p cb %p/%p\n", obj, cb, ctxt);

	if (!obj->sos_obj || !(obj->flags & DSOS_OBJ_CREATED))
		return ENOENT;

	obj->cb   = cb;
	obj->ctxt = ctxt;

	schema = sos_obj_schema(obj->sos_obj);

	args_in = (rpc_obj_index_in_t *)malloc(g.num_servers * sizeof(rpc_obj_index_in_t));
	if (!args_in) {
		ret = ENOMEM;
		goto out;
	}

	for (i = 0; i < g.num_servers; ++i) {
		args_in[i].server_num = i;
		args_in[i].obj        = obj;
		args_in[i].num_attrs  = 0;
		args_in[i].attrs = calloc(sos_schema_attr_count(schema), sizeof(sos_value_t));
		if (!args_in[i].attrs) {
			ret = ENOMEM;
			goto out;
		}
	}

	for (i = 0; i < sos_schema_attr_count(schema); ++i) {
		attr = sos_schema_attr_by_id(schema, i);
		if (!attr->data_.indexed)
			continue;
		v = sos_value(obj->sos_obj, attr);
		server_num = attr_value_to_server(v);
		args_in[server_num].attrs[args_in[server_num].num_attrs++] = v;
		dsos_debug("attr %s (%d) of %d to server %d\n", sos_attr_name(attr),
			   i, args_in[server_num].num_attrs, server_num);
	}

	ret = dsos_rpc_obj_index(args_in);
 out:
	if (ret && obj->cb)
		obj->cb(obj, obj->ctxt);

	for (i = 0; i < g.num_servers; ++i)
		free(args_in[i].attrs);
	free(args_in);

	return ret;
}

sos_obj_t dsos_obj_find(dsos_schema_t *schema, sos_attr_t attr, sos_key_t key)
{
	int			ret, server_num;
	size_t			key_sz;
	char			*key_data;
	sos_obj_t		sos_obj;
	uint8_t			sha[SHA256_DIGEST_LENGTH];
	rpc_obj_find_in_t	args_in_find;
	rpc_obj_find_out_t	args_out_find;
	rpc_obj_get_in_t	args_in_get;
	rpc_obj_get_out_t	args_out_get;

	key_sz   = sos_key_len(key);
	key_data = sos_key_value(key);

	SHA256((const unsigned char *)key_data, key_sz, sha);
	server_num = sha[0] % g.num_servers;

	sos_obj = sos_obj_malloc(schema->sos_schema);
	if (!sos_obj) {
		dsos_error("could not allocate sos_obj\n");
		return NULL;
	}

	args_in_find.server_num    = server_num;
	args_in_find.cont_handle   = schema->cont->handles[server_num];
	args_in_find.schema_handle = schema->handles[server_num];
	args_in_find.attr          = attr;
	args_in_find.key           = key;
	args_in_find.sos_obj       = sos_obj;

	ret = dsos_rpc_obj_find(&args_in_find, &args_out_find);
	if (ret)
		return NULL;

	dsos_debug("obj_id %08lx%08lx\n",
		   args_out_find.obj_id.ref.ods, args_out_find.obj_id.ref.obj);

	// to do: optimize case where the server owning the index also owns the obj

	args_in_get.cont_handle = schema->cont->handles[args_out_find.obj_id.ref.ods];
	args_in_get.obj_id      = args_out_find.obj_id;
	args_in_get.sos_obj     = sos_obj;

	ret = dsos_rpc_obj_get(&args_in_get, &args_out_get);
	if (ret)
		return NULL;

	dsos_debug("obj_id %08lx%08lx sos_obj %p status %ds\n",
		   args_out_find.obj_id.ref.ods, args_out_find.obj_id.ref.obj,
		   sos_obj, args_out_get.status);

	return sos_obj;
}

#include "dsos_priv.h"

int dsos_obj_server(sos_obj_t obj)
{
	return obj->obj_ref.ref.ods;
}

sos_obj_t dsos_obj_alloc(dsos_schema_t *schema)
{
	sos_obj_t obj = sos_obj_malloc(schema->sos_schema);
	if (!obj)
		dsos_fatal("out of memory\n");
	obj->ctxt = schema;
	return obj;
}

sos_obj_t dsos_obj_malloc(dsos_schema_t *schema)
{
	sos_obj_t obj = dsos_obj_alloc(schema);
	if (!obj)
		dsos_fatal("out of memory\n");
	return obj;
}

sos_obj_t *dsos_obj_calloc(int num_objs, dsos_schema_t *schema)
{
	int		i;
	sos_obj_t	*objs = (sos_obj_t *)dsos_malloc(num_objs * sizeof(sos_obj_t *));

	for (i = 0; i < num_objs; ++i)
		objs[i] = dsos_obj_alloc(schema);
	return objs;
}

static void obj_create_cb(dsos_rpc_t *rpc, dsos_rpc_flags_t flags, dsos_buf_t *resp, int server_num, void *ctxt)
{
	sos_obj_t	obj = ctxt;
	dsos_obj_cb_t	cb  = rpc->ctxt2.ptr1;
	dsos_obj_id_t	obj_id;

	obj->obj_ref = dsos_rpc_unpack_obj_id(rpc);

	dsos_debug("obj %p len %d from server %d rpc %p cb %p/%p obj_id %08lx%08lx\n",
		   obj, resp->len, server_num, rpc, rpc->ctxt2.ptr1, rpc->ctxt2.ptr2,
		   obj->obj_ref.ref.ods, obj->obj_ref.ref.obj);

	cb(obj, rpc->ctxt2.ptr2);

	/* Drop the ref taken in dsos_obj_create(). */
	sos_obj_put(obj);
}

int dsos_obj_create(sos_obj_t obj, dsos_obj_cb_t cb, void *ctxt)
{
	int		server_num;
	char		*obj_data;
	size_t		obj_sz;
	uint8_t		sha[SHA256_DIGEST_LENGTH];
	dsos_schema_t	*schema = obj->ctxt;
	dsos_rpc_t	*rpc = dsos_rpc_new(DSOS_RPC_ONE, DSOS_RPC_OBJ_CREATE);

	/* Calculate the owning DSOS server. */
	sos_obj_get(obj);  // this ref is dropped in obj_create_cb()
	sos_obj_data_get(obj, &obj_data, &obj_sz);
	SHA256(obj_data, obj_sz, sha);
	server_num = sha[0] % g.num_servers;

	dsos_rpc_pack_handle(rpc, schema->handles[server_num]);
	if (dsos_rpc_pack_fits(rpc, dsos_rpc_pack_obj_needs(obj) + sizeof(uint32_t))) {
		dsos_rpc_pack_u32_one(rpc, DSOS_RPC_FLAGS_INLINE);
		dsos_rpc_pack_obj(rpc, obj);
	} else {
		dsos_rpc_pack_u32_one(rpc, 0);
		dsos_rpc_pack_obj_ptr(rpc, obj);
	}
	dsos_rpc_set_server(rpc, server_num);

	rpc->ctxt2.ptr1 = cb;
	rpc->ctxt2.ptr2 = ctxt;

	return dsos_rpc_send_cb(rpc, DSOS_RPC_CB, obj_create_cb, obj);
}

static void obj_get_cb(dsos_rpc_t *rpc, dsos_rpc_flags_t flags, dsos_buf_t *resp, int server_num, void *ctxt)
{
	dsos_rpc_unpack_obj(rpc, (sos_obj_t)ctxt);
}

sos_obj_t dsos_obj_get(dsos_schema_t *schema, sos_obj_ref_t ref)
{
	int		ret, server_num;
	sos_obj_t	obj;
	dsos_rpc_t	*rpc = dsos_rpc_new(DSOS_RPC_ONE, DSOS_RPC_OBJ_GET);

	obj = dsos_obj_malloc(schema);

	server_num = ref.ref.ods;

	dsos_rpc_pack_handle(rpc, schema->cont->handles[server_num]);
	dsos_rpc_pack_obj_id_one(rpc, ref);
	dsos_rpc_pack_obj_ptr(rpc, obj);
	dsos_rpc_set_server(rpc, server_num);

	ret = dsos_rpc_send_cb(rpc, DSOS_RPC_WAIT | DSOS_RPC_CB | DSOS_RPC_PUT, obj_get_cb, obj);
	if (ret) {
		sos_obj_put(obj);
		return NULL;
	}
	return obj;
}

int dsos_obj_delete(sos_obj_t obj)
{
	int		ret, server_num;
	dsos_schema_t	*schema = obj->ctxt;
	dsos_rpc_t	*rpc = dsos_rpc_new(DSOS_RPC_ONE, DSOS_RPC_OBJ_DELETE);

	server_num = dsos_obj_server(obj);

	dsos_rpc_pack_handle(rpc, schema->cont->handles[server_num]);
	dsos_rpc_pack_obj_id_one(rpc, obj->obj_ref);

	ret = dsos_rpc_send_one(rpc, DSOS_RPC_WAIT | DSOS_RPC_PUT, server_num);

	sos_obj_put(obj);

	return ret;
}

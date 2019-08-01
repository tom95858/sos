#include "dsos_priv.h"

void dsos_obj_init()
{
	g.obj_create.pending = 0;

	pthread_mutex_init(&g.obj_create.lock, 0);
	pthread_cond_init(&g.obj_create.none_pending, NULL);
}

int dsos_obj_server(sos_obj_t obj)
{
	return obj->obj_ref.ref.ods;
}

// This is the user API call.
sos_obj_t dsos_obj_alloc(sos_schema_t schema)
{
	sos_obj_t obj = sos_obj_malloc(schema);
	if (!obj)
		dsos_fatal("out of memory\n");
	return obj;
}

// This is an internal API for allocating a SOS object.
sos_obj_t dsos_obj_malloc(sos_schema_t schema)
{
	sos_obj_t obj = sos_obj_malloc(schema);
	if (!obj)
		dsos_fatal("out of memory\n");
	return obj;
}

// This is an internal API for allocating num_objs SOS objects.
sos_obj_t *dsos_obj_calloc(int num_objs, sos_schema_t schema)
{
	int		i;
	sos_obj_t	*objs = (sos_obj_t *)dsos_malloc(num_objs * sizeof(sos_obj_t *));

	for (i = 0; i < num_objs; ++i)
		objs[i] = dsos_obj_malloc(schema);
	return objs;
}

static void obj_create_cb(dsos_rpc_t *rpc, dsos_rpc_flags_t flags, dsos_buf_t *resp, int server_num, void *ctxt)
{
	sos_obj_t	obj = ctxt;
	dsos_obj_cb_t	cb  = rpc->ctxt2.ptr1;

	obj->obj_ref = dsos_rpc_unpack_obj_id(rpc);

	dsos_debug("obj %p len %d from server %d rpc %p cb %p/%p obj_id %08lx%08lx\n",
		   obj, resp->len, server_num, rpc, rpc->ctxt2.ptr1, rpc->ctxt2.ptr2,
		   obj->obj_ref.ref.ods, obj->obj_ref.ref.obj);

	/*
	 * If the caller gave a callback, call it. Otherwise it means
	 * they wanted a totally asynchronous object creation, so do
	 * the sos_obj_put() for them.
	 */
	if (cb)
		cb(obj, rpc->ctxt2.ptr2);
	else
		sos_obj_put(obj);

	/* Drop the ref taken in dsos_obj_create(). */
	sos_obj_put(obj);

	dsos_rpc_put(rpc);

	/* Signal any waiters. This is to implement dsos_obj_wait_for_all(). */
	pthread_mutex_lock(&g.obj_create.lock);
	if (--g.obj_create.pending == 0)
		pthread_cond_signal(&g.obj_create.none_pending);
	pthread_mutex_unlock(&g.obj_create.lock);
}

int dsos_obj_create(sos_obj_t obj, dsos_obj_cb_t cb, void *ctxt)

{
	int		server_num;
	char		*obj_data;
	size_t		obj_sz;
	uint8_t		sha[SHA256_DIGEST_LENGTH];
	dsos_rpc_t	*rpc = dsos_rpc_new(DSOS_RPC_ONE, DSOS_RPC_OBJ_CREATE);

	/* Calculate the owning DSOS server. */
	sos_obj_get(obj);  // this ref is dropped in obj_create_cb()
	sos_obj_data_get(obj, &obj_data, &obj_sz);
	SHA256(obj_data, obj_sz, sha);
	server_num = sha[0] % g.num_servers;

	dsos_rpc_pack_handle(rpc, obj->schema->dsos.handles[server_num]);
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

	pthread_mutex_lock(&g.obj_create.lock);
	++g.obj_create.pending;
	pthread_mutex_unlock(&g.obj_create.lock);

	return dsos_rpc_send_cb(rpc, DSOS_RPC_CB, obj_create_cb, obj);
}

static void obj_get_cb(dsos_rpc_t *rpc, dsos_rpc_flags_t flags, dsos_buf_t *resp, int server_num, void *ctxt)
{
	dsos_rpc_unpack_obj(rpc, (sos_obj_t)ctxt);
}

sos_obj_t dsos_obj_get(sos_schema_t schema, sos_obj_ref_t ref)
{
	int		ret, server_num;
	sos_obj_t	obj;
	dsos_t		*cont = schema->dsos.cont;
	dsos_rpc_t	*rpc = dsos_rpc_new(DSOS_RPC_ONE, DSOS_RPC_OBJ_GET);

	obj = dsos_obj_malloc(schema);

	server_num = ref.ref.ods;

	dsos_rpc_pack_handle(rpc, cont->handles[server_num]);
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
	dsos_t		*cont = obj->schema->dsos.cont;
	dsos_rpc_t	*rpc = dsos_rpc_new(DSOS_RPC_ONE, DSOS_RPC_OBJ_DELETE);

	server_num = dsos_obj_server(obj);

	dsos_rpc_pack_handle(rpc, cont->handles[server_num]);
	dsos_rpc_pack_obj_id_one(rpc, obj->obj_ref);

	return dsos_rpc_send_one(rpc, DSOS_RPC_WAIT | DSOS_RPC_PUT, server_num);
}

void dsos_obj_wait_for_all()
{
	pthread_mutex_lock(&g.obj_create.lock);
	while (g.obj_create.pending)
		pthread_cond_wait(&g.obj_create.none_pending, &g.obj_create.lock);
	pthread_mutex_unlock(&g.obj_create.lock);
}

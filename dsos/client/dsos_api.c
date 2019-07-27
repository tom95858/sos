#include "dsos_priv.h"

static int	iter_rbn_cmp_fn(void *tree_key, void *key);

static uint64_t nsecs_now()
{
	struct timespec	ts;

	clock_gettime(CLOCK_REALTIME, &ts);
	return ts.tv_sec * 1.0e+9 + ts.tv_nsec;
}

int dsos_ping_one(int server_num, struct dsos_ping_stats *stats, int debug)
{
	int		len, ret;
	dsos_rpc_t	*rpc = dsos_rpc_new(DSOS_RPC_ONE, DSOS_RPC_PING);

	dsos_rpc_pack_u32_one(rpc, debug);

	ret = dsos_rpc_send_one(rpc, DSOS_RPC_WAIT | DSOS_RPC_PERSIST_RESPONSES, server_num);
	if (ret == 0)
		dsos_rpc_unpack_buf_and_copy(rpc, stats, &len);

	dsos_rpc_put(rpc);
	return ret;
}

static void ping_cb(dsos_rpc_t *rpc, dsos_rpc_flags_t flags, dsos_buf_t *resp, int server_num, void *ctxt)
{
	uint64_t		then = *(uint64_t *)rpc->ctxt2.ptr1;
	uint64_t		now  = nsecs_now();
	struct dsos_ping_stats	*statsp = ctxt;

	dsos_rpc_unpack_buf_and_copy_one(rpc, server_num, &statsp[server_num], NULL);
	statsp[server_num].nsecs = now - then;
}

int dsos_ping_all(struct dsos_ping_stats **statsp, int debug)
{
	uint64_t	now;
	dsos_rpc_t	*rpc = dsos_rpc_new(DSOS_RPC_ALL, DSOS_RPC_PING);

	dsos_rpc_pack_u32_all(rpc, debug);

	*statsp = (struct dsos_ping_stats *)dsos_malloc(g.num_servers *
							sizeof(struct dsos_ping_stats));
	now = nsecs_now();
	rpc->ctxt2.ptr1 = &now;
	return dsos_rpc_send_cb(rpc, DSOS_RPC_WAIT | DSOS_RPC_CB_ALL | DSOS_RPC_PUT, ping_cb, *statsp);
}

int dsos_container_new(const char *path, int mode)
{
	dsos_rpc_t *rpc = dsos_rpc_new(DSOS_RPC_ALL, DSOS_RPC_CONT_NEW);

	dsos_rpc_pack_u32_all(rpc, mode);
	dsos_rpc_pack_str_all(rpc, path);

	return dsos_rpc_send(rpc, DSOS_RPC_WAIT | DSOS_RPC_PUT);
}

dsos_t *dsos_container_open(const char *path, sos_perm_t perms)
{
	int		ret;
	dsos_t		*cont = NULL;
	dsos_rpc_t	*rpc  = dsos_rpc_new(DSOS_RPC_ALL, DSOS_RPC_CONT_OPEN);

	dsos_rpc_pack_u32_all(rpc, perms);
	dsos_rpc_pack_str_all(rpc, path);

	ret = dsos_rpc_send(rpc, DSOS_RPC_WAIT | DSOS_RPC_PERSIST_RESPONSES);
	if (ret)
		goto out;

	cont = (dsos_t *)dsos_malloc(sizeof(dsos_t));
	cont->handles = dsos_rpc_unpack_handles(rpc);
 out:
	dsos_rpc_put(rpc);
	return cont;
}

void dsos_container_close(dsos_t *cont, int commit)
{
	dsos_rpc_t *rpc = dsos_rpc_new(DSOS_RPC_ALL, DSOS_RPC_CONT_CLOSE);

	dsos_rpc_pack_handles(rpc, cont->handles);
	dsos_rpc_pack_u32_all(rpc, commit);

	free(cont->handles);
	free(cont);

	dsos_rpc_send(rpc, DSOS_RPC_WAIT | DSOS_RPC_PUT);
}

/* For debug, verify sameness of all returned schema. */
static void compare_all_returned_schema(dsos_rpc_t *rpc)
{
#if 1
	int	i;

	for (i = 0; i < g.num_servers; ++i) {
		void *buf1 = rpc->bufs[0].resp.msg + 1;
		void *buf2 = rpc->bufs[i].resp.msg + 1;
		if (memcmp(buf1, buf2, rpc->bufs[0].resp.len - sizeof(dsos_msg_hdr_t)))
			dsos_error("schema from servers 0 and %d differ\n", i);
	}
#endif
}

sos_schema_t dsos_schema_by_name(dsos_t *cont, const char *name)
{
	int		i, ret;
	uint64_t	*handles;
	sos_schema_t	schema = NULL;
	dsos_rpc_t	*rpc = dsos_rpc_new(DSOS_RPC_ALL, DSOS_RPC_SCHEMA_BY_NAME);

	dsos_rpc_pack_handles(rpc, cont->handles);
	dsos_rpc_pack_str_all(rpc, name);

	ret = dsos_rpc_send(rpc, DSOS_RPC_WAIT | DSOS_RPC_PERSIST_RESPONSES);
	if (ret)
		goto out;

	handles = dsos_rpc_unpack_handles(rpc);
	schema  = dsos_rpc_unpack_schema_one(rpc, 0);

	schema->dsos.handles = handles;
	schema->dsos.cont    = cont;

	compare_all_returned_schema(rpc);
 out:
	dsos_rpc_put(rpc);
	return schema;
}

sos_schema_t dsos_schema_by_id(dsos_t *cont, int id)
{
	int		i, ret;
	uint64_t	*handles;
	sos_schema_t	schema = NULL;
	dsos_rpc_t	*rpc = dsos_rpc_new(DSOS_RPC_ALL, DSOS_RPC_SCHEMA_BY_ID);

	dsos_rpc_pack_handles(rpc, cont->handles);
	dsos_rpc_pack_u32_all(rpc, id);

	ret = dsos_rpc_send(rpc, DSOS_RPC_WAIT | DSOS_RPC_PERSIST_RESPONSES);
	if (ret)
		goto out;

	handles = dsos_rpc_unpack_handles(rpc);
	schema  = dsos_rpc_unpack_schema_one(rpc, 0);

	schema->dsos.handles = handles;
	schema->dsos.cont    = cont;

	compare_all_returned_schema(rpc);
 out:
	dsos_rpc_put(rpc);
	return schema;
}

int dsos_schema_add(dsos_t *cont, sos_schema_t schema)
{
	int		ret;
	dsos_rpc_t	*rpc = dsos_rpc_new(DSOS_RPC_ALL, DSOS_RPC_SCHEMA_ADD);

	dsos_rpc_pack_handles(rpc, cont->handles);
	dsos_rpc_pack_schema_all(rpc, schema);

	ret = dsos_rpc_send(rpc, DSOS_RPC_WAIT | DSOS_RPC_PERSIST_RESPONSES);
	if (ret)
		goto out;

	schema->dsos.cont    = cont;
	schema->dsos.handles = dsos_rpc_unpack_handles(rpc);
 out:
	dsos_rpc_put(rpc);
	return ret;
}

sos_schema_t dsos_schema_first(dsos_t *cont)
{
	int		i, ret;
	uint64_t	*handles;
	sos_schema_t	schema = NULL;
	dsos_rpc_t	*rpc = dsos_rpc_new(DSOS_RPC_ALL, DSOS_RPC_SCHEMA_FIRST);

	dsos_rpc_pack_handles(rpc, cont->handles);

	ret = dsos_rpc_send(rpc, DSOS_RPC_WAIT | DSOS_RPC_PERSIST_RESPONSES);
	if (ret)
		goto out;

	handles = dsos_rpc_unpack_handles(rpc);
	schema  = dsos_rpc_unpack_schema_one(rpc, 0);

	schema->dsos.handles = handles;
	schema->dsos.cont    = cont;

	compare_all_returned_schema(rpc);
 out:
	dsos_rpc_put(rpc);
	return schema;
}

sos_schema_t dsos_schema_next(sos_schema_t schema)
{
	int		i, ret;
	uint64_t	*handles;
	sos_schema_t	next_schema = NULL;
	dsos_rpc_t	*rpc = dsos_rpc_new(DSOS_RPC_ALL, DSOS_RPC_SCHEMA_NEXT);

	dsos_rpc_pack_handles(rpc, schema->dsos.handles);

	ret = dsos_rpc_send(rpc, DSOS_RPC_WAIT | DSOS_RPC_PERSIST_RESPONSES);
	if (ret)
		goto out;

	handles     = dsos_rpc_unpack_handles(rpc);
	next_schema = dsos_rpc_unpack_schema_one(rpc, 0);

	next_schema->dsos.handles = handles;
	next_schema->dsos.cont    = schema->dsos.cont;

	compare_all_returned_schema(rpc);
 out:
	dsos_rpc_put(rpc);
	return next_schema;
}

int dsos_part_create(dsos_t *cont, const char *part_name, const char *part_path)
{
	dsos_rpc_t *rpc = dsos_rpc_new(DSOS_RPC_ALL, DSOS_RPC_PART_CREATE);

	dsos_rpc_pack_handles(rpc, cont->handles);
	dsos_rpc_pack_str_all(rpc, part_name);
	dsos_rpc_pack_str_all(rpc, part_path);

	return dsos_rpc_send(rpc, DSOS_RPC_WAIT | DSOS_RPC_PUT);
}

dsos_part_t *dsos_part_find(dsos_t *cont, const char *name)
{
	int		ret;
	dsos_part_t	*part;
	dsos_rpc_t	*rpc  = dsos_rpc_new(DSOS_RPC_ALL, DSOS_RPC_PART_FIND);

	dsos_rpc_pack_handles(rpc, cont->handles);
	dsos_rpc_pack_str_all(rpc, name);

	ret = dsos_rpc_send(rpc, DSOS_RPC_WAIT | DSOS_RPC_PERSIST_RESPONSES);
	if (ret)
		goto out;

	part = (dsos_part_t *)dsos_malloc(sizeof(dsos_part_t));

	part->handles = dsos_rpc_unpack_handles(rpc);
 out:
	dsos_rpc_put(rpc);
	return part;
}

int dsos_part_state_set(dsos_part_t *part, sos_part_state_t new_state)
{
	dsos_rpc_t *rpc = dsos_rpc_new(DSOS_RPC_ALL, DSOS_RPC_PART_SET_STATE);

	dsos_rpc_pack_u32_all(rpc, new_state);
	dsos_rpc_pack_handles(rpc, part->handles);

	return dsos_rpc_send(rpc, DSOS_RPC_WAIT | DSOS_RPC_PUT);
}

static int iter_rbn_cmp_fn(void *tree_key, void *key)
{
	return sos_value_cmp((sos_value_t)tree_key, (sos_value_t)key);
}

static void iter_rbt_insert(dsos_iter_t *iter, sos_value_t v, sos_obj_t obj)
{
	struct iter_rbn	*rbn = calloc(1, sizeof(struct iter_rbn));
	if (!rbn)
		dsos_fatal("out of memory");
	rbn->rbn.key = (void *)v;
	rbn->obj     = obj;

	rbt_ins(&iter->rbt, (void *)rbn);

	dsos_debug("iter %p inserted value %ld from obj %08lx%08lx\n",
		   iter, v->data->prim.uint64_, obj->obj_ref.ref.ods, obj->obj_ref.ref.obj);
}

static void iter_insert_obj(dsos_iter_t *iter, sos_obj_t obj)
{
	iter_rbt_insert(iter, sos_value(obj, iter->attr), obj);
}

static sos_obj_t iter_rbt_min(dsos_iter_t *iter)
{
	sos_obj_t	obj = NULL;
	struct iter_rbn	*rbn;

	rbn = (struct iter_rbn *)rbt_min(&iter->rbt);
	if (rbn) {
		obj = rbn->obj;
		dsos_debug("iter %p min value %ld obj_id %08lx%08lx\n",
			   iter, ((sos_value_t)rbn->rbn.key)->data->prim.uint64_,
			   obj->obj_ref.ref.ods, obj->obj_ref.ref.obj);
		rbt_del(&iter->rbt, (struct rbn *)rbn);
		sos_value_put(rbn->rbn.key);
		sos_value_free(rbn->rbn.key);
		free(rbn);
	} else
		dsos_debug("iter %p rbt empty\n", iter);

	return obj;
}

static sos_obj_t iter_get_min(dsos_iter_t *iter)
{
	sos_obj_t	obj = NULL;
	struct iter_rbn	*rbn;

	rbn = (struct iter_rbn *)rbt_min(&iter->rbt);
	if (rbn) {
		obj = rbn->obj;
		dsos_debug("iter %p min value %ld obj_id %08lx%08lx\n",
			   iter, ((sos_value_t)rbn->rbn.key)->data->prim.uint64_,
			   obj->obj_ref.ref.ods, obj->obj_ref.ref.obj);
	} else {
		dsos_debug("iter %p rbt empty\n", iter);
	}
	if (!obj) {
		iter->done = 1;
		iter->last_server = -1;
	}
	return obj;
}

static void iter_remove_min(dsos_iter_t *iter)
{
	sos_obj_t	obj;
	struct iter_rbn	*rbn;

	rbn = (struct iter_rbn *)rbt_min(&iter->rbt);
	if (rbn) {
		obj = rbn->obj;
		dsos_debug("iter %p min value %ld obj_id %08lx%08lx\n",
			   iter, ((sos_value_t)rbn->rbn.key)->data->prim.uint64_,
			   obj->obj_ref.ref.ods, obj->obj_ref.ref.obj);
		rbt_del(&iter->rbt, (struct rbn *)rbn);
		sos_value_put(rbn->rbn.key);
		sos_value_free(rbn->rbn.key);
		free(rbn);
	} else {
		dsos_debug("iter %p rbt empty\n", iter);
	}
	if (!obj) {
		iter->done = 1;
		iter->last_server = -1;
	} else {
		iter->last_server = dsos_obj_server(obj);
		sos_obj_put(obj);
	}
}

static int iter_reset(dsos_iter_t *iter)
{
	sos_obj_t	obj;

	/* Ignore the response to any pending prefetch. */
	iter->prefetch_rpc = NULL;

	/* Clear out the rbt. */
	while (obj = iter_rbt_min(iter))
		sos_obj_put(obj);

	iter->last_server = -1;
	iter->done = 0;
	rbt_init(&iter->rbt, iter_rbn_cmp_fn);

	return 0;
}

static void iter_prefetch_cb(dsos_rpc_t *rpc, dsos_rpc_flags_t flags, dsos_buf_t *resp, int server_num, void *ctxt)
{
	dsos_iter_t	*iter = (dsos_iter_t *)ctxt;
	sos_obj_t	obj   = (sos_obj_t)rpc->ctxt2.ptr1;

	pthread_mutex_lock(&iter->lock);

	dsos_debug("rpc %p got obj %p iter %p done %d prefetch_rpc %p status %d from server %d\n",
		   rpc, obj, iter, iter->done, iter->prefetch_rpc, resp->msg->hdr.status,
		   rpc->server_num);

	if (iter->done) {
		pthread_mutex_unlock(&iter->lock);
		return;
	}
	if (rpc != iter->prefetch_rpc) {
		/* This response has been cancelled. Ignore it. */
		dsos_debug("ignoring\n");
		sos_obj_put(obj);
		pthread_mutex_unlock(&iter->lock);
		return;
	}

	switch (dsos_err_get_remote(rpc->status, server_num)) {
	    case 0:
		obj->obj_ref = dsos_rpc_unpack_obj_id(rpc);
		if (dsos_rpc_unpack_u32(rpc) & DSOS_RPC_FLAGS_INLINE)
			dsos_rpc_unpack_obj(rpc, obj);
		iter_insert_obj(iter, obj);
		iter->status = 0;
		break;
	    case ENOENT:
		dsos_debug("iter %p server %d is done\n", iter, server_num);
		sos_obj_put(obj);
		dsos_err_set_remote(rpc->status, server_num, 0);
		iter->status = 0;
		break;
	    default:
		sos_obj_put(obj);
		iter->status = dsos_err_get_remote(rpc->status, server_num);
		dsos_error("rpc %p iter %p status %d from server %d\n",
			   rpc, iter, iter->status, server_num);
		break;
	}

	dsos_debug("signalling\n");
	iter->prefetch_rpc = NULL;
	pthread_cond_signal(&iter->prefetch_complete);
	pthread_mutex_unlock(&iter->lock);
}

static int iter_prefetch(dsos_iter_t *iter, int server_num, dsos_rpc_type_t rpc_type, int op)
{
	sos_obj_t	obj;
	dsos_rpc_t	*rpc = dsos_rpc_new(DSOS_RPC_ONE, rpc_type);

	if (iter->done)
		return 0;

	obj = dsos_obj_malloc(iter->schema);

	dsos_rpc_pack_u32_one(rpc, op);
	dsos_rpc_pack_handle(rpc, iter->handles[server_num]);
	dsos_rpc_pack_obj_ptr(rpc, obj);
	dsos_rpc_pack_key_one(rpc, NULL);
	dsos_rpc_set_server(rpc, server_num);

	iter->prefetch_rpc = rpc;
	rpc->ctxt2.ptr1    = obj;

	dsos_debug("from server %d into obj %p iter %p prefetch_rpc %p\n",
		   server_num, obj, iter, iter->prefetch_rpc);

	return dsos_rpc_send_cb(rpc, DSOS_RPC_CB | DSOS_RPC_PUT, iter_prefetch_cb, iter);
}

dsos_iter_t *dsos_attr_iter_new(sos_attr_t attr)
{
	int		ret;
	dsos_iter_t	*iter = NULL;
	sos_schema_t	schema = sos_attr_schema(attr);
	dsos_rpc_t	*rpc = dsos_rpc_new(DSOS_RPC_ALL, DSOS_RPC_ITER_NEW);

	dsos_rpc_pack_u32_all(rpc, sos_attr_id(attr));
	dsos_rpc_pack_handles(rpc, schema->dsos.handles);

	ret = dsos_rpc_send(rpc, DSOS_RPC_WAIT | DSOS_RPC_PERSIST_RESPONSES);
	if (ret)
		goto out;

	iter = (dsos_iter_t *)dsos_malloc(sizeof(dsos_iter_t));

	iter->handles     = dsos_rpc_unpack_handles(rpc);
	iter->attr        = attr;
	iter->schema      = schema;
	iter->last_op     = DSOS_RPC_ITER_OP_NONE;
	iter->done        = 0;
	iter->status      = 0;
	iter->last_server = -1;
	iter->obj_sz      = schema->data->obj_sz + schema->data->array_data_sz;
	pthread_mutex_init(&iter->lock, 0);
	pthread_cond_init(&iter->prefetch_complete, NULL);
	rbt_init(&iter->rbt, iter_rbn_cmp_fn);
 out:
	dsos_rpc_put(rpc);
	return iter;
}

void dsos_iter_free(dsos_iter_t *iter)
{
	sos_obj_t	obj;
	dsos_rpc_t	*rpc = dsos_rpc_new(DSOS_RPC_ALL, DSOS_RPC_ITER_CLOSE);

	dsos_rpc_pack_handles(rpc, iter->handles);

	while (obj = iter_rbt_min(iter))
		sos_obj_put(obj);
	free(iter->handles);
	free(iter);

	dsos_rpc_send(rpc, DSOS_RPC_WAIT | DSOS_RPC_PUT);
}

static void iter_cb(dsos_rpc_t *rpc, dsos_rpc_flags_t flags, dsos_buf_t *buf, int server_num, void *ctxt)
{
	dsos_iter_t	*iter = (dsos_iter_t *)ctxt;
	sos_obj_t	*objs = (sos_obj_t *)rpc->ctxt2.ptr1;

	switch (dsos_err_get_remote(rpc->status, server_num)) {
	    case 0:
		objs[server_num]->obj_ref = dsos_rpc_unpack_obj_id_one(rpc, server_num);
		if (dsos_rpc_unpack_u32_one(rpc, server_num) & DSOS_RPC_FLAGS_INLINE)
			dsos_rpc_unpack_obj_one(rpc, server_num, objs[server_num]);
		pthread_mutex_lock(&iter->lock);
		iter_insert_obj(iter, objs[server_num]);
		pthread_mutex_unlock(&iter->lock);
		break;
	    case ENOENT:
		sos_obj_put(objs[server_num]);
		dsos_err_set_remote(rpc->status, server_num, 0);
		break;
	    default:
		dsos_error("rpc %p iter %p status %d from server %d\n",
			   rpc, iter,
			   dsos_err_get_remote(rpc->status, server_num),
			   server_num);
		sos_obj_put(objs[server_num]);
		break;
	}
}

static int iter_begin(dsos_iter_t *iter, dsos_rpc_type_t rpc_type, int op)
{
	int		i, ret;
	sos_obj_t	obj = NULL, *objs;
	dsos_rpc_t	*rpc = dsos_rpc_new(DSOS_RPC_ALL, rpc_type);

	pthread_mutex_lock(&iter->lock);
	ret = iter_reset(iter);
	pthread_mutex_unlock(&iter->lock);

	objs = dsos_obj_calloc(g.num_servers, iter->schema);

	dsos_rpc_pack_u32_all(rpc, op);
	dsos_rpc_pack_handles(rpc, iter->handles);
	dsos_rpc_pack_obj_ptrs(rpc, objs);
	dsos_rpc_pack_key_all(rpc, NULL);

	rpc->ctxt2.ptr1 = objs;

	ret = dsos_rpc_send_cb(rpc, DSOS_RPC_WAIT | DSOS_RPC_CB_ALL | DSOS_RPC_PUT, iter_cb, iter);
	if (ret)
		goto out;

	pthread_mutex_lock(&iter->lock);
	obj = iter_get_min(iter);
	pthread_mutex_unlock(&iter->lock);
 out:
	free(objs);
	return obj ? 0 : ENOENT;
}

int dsos_iter_begin(dsos_iter_t *iter)
{
	return iter_begin(iter, DSOS_RPC_ITER_STEP, DSOS_RPC_ITER_OP_BEGIN);
}

sos_obj_t dsos_filter_begin(dsos_filter_t *filter)
{
	iter_begin(filter->iter, DSOS_RPC_FILTER_STEP, DSOS_RPC_FILTER_OP_BEGIN);
	return dsos_iter_obj(filter->iter);
}

sos_obj_t dsos_iter_obj(dsos_iter_t *iter)
{
	sos_obj_t	obj;

	pthread_mutex_lock(&iter->lock);
	obj = iter_get_min(iter);
	pthread_mutex_unlock(&iter->lock);

	if (obj)
		sos_obj_get(obj);  // caller must put this ref

	return obj;
}

static int iter_next(dsos_iter_t *iter, dsos_rpc_type_t rpc_type, int op)
{
	int		ret;
	sos_obj_t	obj = NULL;

	pthread_mutex_lock(&iter->lock);

	dsos_debug("iter %p prefetch_rpc %p\n", iter, iter->prefetch_rpc);

	if (iter->done)
		goto out;

	iter_remove_min(iter);

#ifndef ITER_PREFETCH
	assert(iter->last_server != -1);
	iter_prefetch(iter, iter->last_server, rpc_type, op);
#endif
	/* Wait for the previously prefetched object. */
	while (iter->prefetch_rpc)
		pthread_cond_wait(&iter->prefetch_complete, &iter->lock);

	if (iter->status)
		goto out;

	obj = iter_get_min(iter);
 out:
	pthread_mutex_unlock(&iter->lock);
	return obj ? 0 : ENOENT;
}

int dsos_iter_next(dsos_iter_t *iter)
{
	return iter_next(iter, DSOS_RPC_ITER_STEP, DSOS_RPC_ITER_OP_NEXT);
}

sos_obj_t dsos_filter_next(dsos_filter_t *filter)
{
	iter_next(filter->iter, DSOS_RPC_FILTER_STEP, DSOS_RPC_FILTER_OP_NEXT);
	return dsos_iter_obj(filter->iter);
}

int dsos_iter_find(dsos_iter_t *iter, sos_key_t key)
{
	int		i, ret;
	sos_obj_t	obj = NULL, *objs;
	dsos_rpc_t	*rpc = dsos_rpc_new(DSOS_RPC_ALL, DSOS_RPC_ITER_STEP);

	pthread_mutex_lock(&iter->lock);
	ret = iter_reset(iter);
	pthread_mutex_unlock(&iter->lock);

	objs = dsos_obj_calloc(g.num_servers, iter->schema);

	dsos_rpc_pack_u32_all(rpc, DSOS_RPC_ITER_OP_FIND);
	dsos_rpc_pack_handles(rpc, iter->handles);
	dsos_rpc_pack_obj_ptrs(rpc, objs);
	dsos_rpc_pack_key_all(rpc, key);

	rpc->ctxt2.ptr1 = objs;

	ret = dsos_rpc_send_cb(rpc, DSOS_RPC_WAIT | DSOS_RPC_CB_ALL | DSOS_RPC_PUT, iter_cb, iter);
	if (ret)
		goto out;

	pthread_mutex_lock(&iter->lock);
	obj = iter_get_min(iter);
	pthread_mutex_unlock(&iter->lock);
 out:
	free(objs);
	return obj ? 0 : ENOENT;
}

int dsos_iter_end(dsos_iter_t *iter)
{
	return ENOSYS;
}

int dsos_iter_sup(dsos_iter_t *iter, sos_key_t key)
{
	return ENOSYS;
}

int dsos_iter_inf(dsos_iter_t *iter, sos_key_t key)
{
	return ENOSYS;
}

sos_key_t dsos_iter_key(dsos_iter_t *iter)
{
	return NULL;
}

sos_iter_flags_t dsos_iter_flags_get(dsos_iter_t *iter)
{
	return 0;
}

void dsos_iter_flags_set(dsos_iter_t *iter, sos_iter_flags_t flags)
{
}

int dsos_iter_pos_get(dsos_iter_t *iter, sos_pos_t *pos)
{
	return ENOSYS;
}

int dsos_iter_pos_put(dsos_iter_t *iter, sos_pos_t pos)
{
	return ENOSYS;
}

int dsos_iter_pos_set(dsos_iter_t *iter, sos_pos_t pos)
{
	return ENOSYS;
}

int dsos_iter_prev(dsos_iter_t *iter)
{
	return ENOSYS;
}

/* Indices */

int dsos_attr_is_indexed(sos_attr_t attr)
{
	return attr->data->indexed;
}

dsos_index_t *dsos_attr_index(sos_attr_t attr)
{
	return NULL;
}

sos_obj_t dsos_index_find(dsos_index_t *index, sos_key_t key)
{
	return NULL;
}

int dsos_index_find_ref(dsos_index_t *index, sos_key_t key, sos_obj_ref_t *ref)
{
	return ENOSYS;
}

sos_obj_t dsos_index_find_inf(dsos_index_t *index, sos_key_t key)
{
	return NULL;
}

sos_obj_t dsos_index_find_sup(dsos_index_t *index, sos_key_t key)
{
	return NULL;
}

sos_obj_t dsos_index_find_min(dsos_index_t *index, sos_key_t *key)
{
	return NULL;
}

sos_obj_t dsos_index_find_max(dsos_index_t *index, sos_key_t *key)
{
	return NULL;
}

int dsos_index_find_min_ref(dsos_index_t *index, sos_key_t *key, sos_obj_ref_t *ref)
{
	return ENOSYS;
}

int dsos_index_find_max_ref(dsos_index_t *index, sos_key_t *key, sos_obj_ref_t *ref)
{
	return ENOSYS;
}

int dsos_index_stat(dsos_index_t *index, sos_index_stat_t stats)
{
	return ENOSYS;
}

void dsos_index_print(dsos_index_t *index, FILE *f)
{
}

/* Containers -- not implemented */

int dsos_container_commit(dsos_t *cont, int commit)
{
	return ENOSYS;
}

int dsos_container_version(dsos_t *cont)
{
	return ENOSYS;
}

dsos_container_index_iter_t *dsos_container_index_iter_new(dsos_t *cont)
{
	return NULL;
}

dsos_index_t *dsos_container_index_iter_first(dsos_container_index_iter_t *cont_iter)
{
	return NULL;
}

dsos_index_t *dsos_container_index_iter_next(dsos_container_index_iter_t *cont_iter)
{
	return NULL;
}

void dsos_container_index_iter_free(dsos_container_index_iter_t *cont_iter)
{
}

/* Indices -- not implemented */

int dsos_obj_index(sos_obj_t obj)
{
	return ENOSYS;
}

int dsos_obj_remove(sos_obj_t obj)
{
	return ENOSYS;
}

int dsos_index_new(dsos_t *cont, const char *name, const char *idx_type,
          sos_type_t key_type, const char *args)
{
	return ENOSYS;
}

dsos_index_t *dsos_index_open(dsos_t *cont, const char *name)
{
	return NULL;
}

int dsos_index_insert(dsos_index_t *index, sos_key_t key, sos_obj_t obj)
{
	return ENOSYS;
}

int dsos_index_remove(dsos_index_t *index, sos_key_t key, sos_obj_t obj)
{
	return ENOSYS;
}

const char *dsos_index_name(dsos_index_t *index)
{
	return NULL;
}

sos_type_t dsos_index_key_type(dsos_index_t *index)
{
	return 0;
}

int dsos_index_insert_ref(dsos_index_t *index, sos_key_t key, sos_obj_ref_t ref)
{
	return ENOSYS;
}

int dsos_index_remove_ref(dsos_index_t *index, sos_key_t key, sos_obj_ref_t *ref)
{
	return ENOSYS;
}

/* Partitions -- not implemented */

int dsos_part_id(dsos_part_t *part)
{
	return ENOSYS;
}

char *dsos_part_name(dsos_part_t *part)
{
	return NULL;
}

char *dsos_part_path(dsos_part_t *part)
{
	return NULL;
}

int dsos_part_delete(dsos_part_t *part)
{
	return ENOSYS;
}

int dsos_part_move(dsos_part_t *part, const char *new_path)
{
	return ENOSYS;
}

int dsos_part_export(dsos_part_t *part, dsos_t *dst_cont, int reindex)
{
	return ENOSYS;
}

int dsos_part_index(dsos_part_t *part)
{
	return ENOSYS;
}

void dsos_part_put(dsos_part_t *part)
{
}

dsos_part_iter_t *dsos_part_iter_new(dsos_t *cont)
{
	return NULL;
}

dsos_part_t *dsos_part_first(dsos_part_iter_t *part_iter)
{
	return NULL;
}

dsos_part_t *dsos_part_next(dsos_part_iter_t *part_iter)
{
	return NULL;
}

void dsos_part_iter_free(dsos_part_iter_t *part_iter)
{
}

int dsos_part_stat(dsos_part_t *part, struct sos_part_stat_s *stats)
{
	return ENOSYS;
}

int dsos_part_state(dsos_part_t *part)
{
	return ENOSYS;
}

/* Filters */

char *dsos_pos_to_str(sos_pos_t pos)
{
	return NULL;
}

int dsos_pos_from_str(sos_pos_t *pos, const char *str)
{
	return ENOSYS;
}

int dsos_filter_pos_get(dsos_filter_t *filter, sos_pos_t *pos)
{
	return ENOSYS;
}

int dsos_filter_pos_set(dsos_filter_t *filter, sos_pos_t pos)
{
	return ENOSYS;
}

int dsos_filter_pos_put(dsos_filter_t *filter, sos_pos_t pos)
{
	return ENOSYS;
}

dsos_filter_t *dsos_filter_new(dsos_iter_t *iter)
{
	int		ret;
	dsos_filter_t	*filter;
	dsos_rpc_t	*rpc  = dsos_rpc_new(DSOS_RPC_ALL, DSOS_RPC_FILTER_NEW);

	dsos_rpc_pack_handles(rpc, iter->handles);

	ret = dsos_rpc_send(rpc, DSOS_RPC_WAIT | DSOS_RPC_PERSIST_RESPONSES);
	if (ret)
		goto out;

	filter = (dsos_filter_t *)dsos_malloc(sizeof(dsos_filter_t));
	filter->iter          = iter;
	filter->iter->handles = dsos_rpc_unpack_handles(rpc);
 out:
	dsos_rpc_put(rpc);
	return filter;
}

void dsos_filter_free(dsos_filter_t *filter)
{
	dsos_rpc_t *rpc = dsos_rpc_new(DSOS_RPC_ALL, DSOS_RPC_FILTER_FREE);

	dsos_rpc_pack_handles(rpc, filter->iter->handles);

	free(filter->iter);
	free(filter);

	dsos_rpc_send(rpc, DSOS_RPC_WAIT | DSOS_RPC_PUT);
}

int dsos_filter_cond_add(dsos_filter_t *filter, sos_attr_t attr, sos_cond_t cond, sos_value_t value)
{
	dsos_rpc_t *rpc = dsos_rpc_new(DSOS_RPC_ALL, DSOS_RPC_FILTER_COND_ADD);

	dsos_rpc_pack_handles(rpc, filter->iter->handles);
	dsos_rpc_pack_attr_all(rpc, attr);
	dsos_rpc_pack_u32_all(rpc, cond);
	dsos_rpc_pack_value_all(rpc, value);

	return dsos_rpc_send(rpc, DSOS_RPC_WAIT | DSOS_RPC_PUT);
}

sos_iter_flags_t dsos_filter_flags_get(dsos_filter_t *filter)
{
	int		ret;
	dsos_rpc_t	*rpc  = dsos_rpc_new(DSOS_RPC_ALL, DSOS_RPC_FILTER_FLAGS_GET);

	dsos_rpc_pack_handles(rpc, filter->iter->handles);

	ret = dsos_rpc_send(rpc, DSOS_RPC_WAIT | DSOS_RPC_PERSIST_RESPONSES);
	if (ret)
		return 0;
	ret = dsos_rpc_unpack_u32(rpc);
	dsos_rpc_put(rpc);
	return ret;
}

void dsos_filter_flags_set(dsos_filter_t *filter, sos_iter_flags_t flags)
{
	dsos_rpc_t *rpc = dsos_rpc_new(DSOS_RPC_ALL, DSOS_RPC_FILTER_FLAGS_SET);

	dsos_rpc_pack_u32_all(rpc, flags);

	dsos_rpc_send(rpc, DSOS_RPC_WAIT | DSOS_RPC_PUT);
}

sos_obj_t dsos_filter_end(dsos_filter_t *filter)
{
	return NULL;
}

sos_obj_t dsos_filter_prev(dsos_filter_t *filter)
{
	return NULL;
}

sos_obj_t dsos_filter_obj(dsos_filter_t *filter)
{
	return dsos_iter_obj(filter->iter);
}

int dsos_filter_miss_count(dsos_filter_t *filter)
{
	int		ret;
	dsos_rpc_t	*rpc  = dsos_rpc_new(DSOS_RPC_ALL, DSOS_RPC_FILTER_MISS_COUNT);

	dsos_rpc_pack_handles(rpc, filter->iter->handles);

	ret = dsos_rpc_send(rpc, DSOS_RPC_WAIT | DSOS_RPC_PERSIST_RESPONSES);
	if (ret)
		return 0;
	ret = dsos_rpc_unpack_u32(rpc);
	dsos_rpc_put(rpc);
	return ret;
}

#include "dsos_priv.h"

static int	iter_rbn_cmp_fn(void *tree_key, void *key);

int dsos_ping_one(int server_num, struct dsos_ping_stats *stats)
{
	int			ret;
	rpc_ping_in_t		args_in;
	rpc_ping_out_t		args_out;

	args_in.server_num = server_num;
	args_in.stats      = stats;

	return dsos_rpc_ping_one(&args_in, &args_out);
}

int dsos_ping_all(struct dsos_ping_stats **statsp, int debug)
{
	int                     ret;
	rpc_ping_in_t		args_in;
	rpc_ping_out_t          args_outp;

	args_in.debug = debug;

	ret = dsos_rpc_ping_all(&args_in, &args_outp);

	*statsp = args_outp.stats;

	return ret;
}

int dsos_container_new(const char *path, int mode)
{
	rpc_container_new_in_t		args_in;
	rpc_container_new_out_t		args_out;

	strncpy(args_in.path, path, sizeof(args_in.path));
	args_in.mode = mode;

	return dsos_rpc_container_new(&args_in, &args_out);
}

dsos_t *dsos_container_open(const char *path, sos_perm_t perms)
{
	int				ret;
	dsos_t				*cont;
	rpc_container_open_in_t		args_in;
	rpc_container_open_out_t	args_out;

	strncpy(args_in.path, path, sizeof(args_in.path));
	args_in.perms = perms;

	ret = dsos_rpc_container_open(&args_in, &args_out);
	if (ret)
		return NULL;

	cont = (dsos_t *)malloc(sizeof(dsos_t));
	if (!cont)
		dsos_fatal("out of memory\n");
	cont->handles = args_out.handles;

	return cont;
}

int dsos_container_close(dsos_t *cont)
{
	int				ret;
	rpc_container_close_in_t	args_in;
	rpc_container_close_out_t	args_out;

	args_in.handles = cont->handles;

	ret = dsos_rpc_container_close(&args_in, &args_out);

	free(cont->handles);
	free(cont);

	return ret;
}

dsos_schema_t *dsos_schema_by_name(dsos_t *cont, const char *name)
{
	int				ret;
	dsos_schema_t			*schema;
	sos_schema_template_t		template;
	rpc_schema_by_name_in_t		args_in;
	rpc_schema_by_name_out_t	args_out;

	strncpy(args_in.name, name, sizeof(args_in.name));
	args_in.cont_handles = cont->handles;

	ret = dsos_rpc_schema_by_name(&args_in, &args_out);
	if (ret)
		return NULL;

	template = dsos_rpc_deserialize_schema_template(args_out.templ,
							sizeof(args_out.templ));

	schema = (dsos_schema_t *)malloc(sizeof(dsos_schema_t));
	if (!schema)
		dsos_fatal("out of memory\n");
	schema->handles    = args_out.handles;
	schema->sos_schema = sos_schema_from_template(template);
	schema->cont       = cont;

	free(template);
	return schema;
}

int dsos_schema_add(dsos_t *cont, dsos_schema_t *schema)
{
	rpc_schema_add_in_t		args_in;
	rpc_schema_add_out_t		args_out;

	args_in.cont_handles   = cont->handles;
	args_in.schema_handles = schema->handles;

	return dsos_rpc_schema_add(&args_in, &args_out);
}

dsos_schema_t *dsos_schema_from_template(sos_schema_template_t t)
{
	int					ret;
	size_t					template_sz;
	void					*p;
	dsos_schema_t				*schema;
	rpc_schema_from_template_in_t		args_in;
	rpc_schema_from_template_out_t		args_out;

	template_sz = sizeof(args_in.templ);
	p = dsos_rpc_serialize_schema_template(t, args_in.templ, &template_sz);
	if (!p)
		return NULL; // too large to serialize
	args_in.len = template_sz;
	ret = dsos_rpc_schema_from_template(&args_in, &args_out);
	if (ret)
		return NULL;

	schema = (dsos_schema_t *)malloc(sizeof(dsos_schema_t));
	if (!schema)
		dsos_fatal("out of memory\n");
	schema->handles    = args_out.handles;
	schema->sos_schema = sos_schema_from_template(t);

	return schema;
}

int dsos_part_create(dsos_t *cont, const char *part_name, const char *part_path)
{
	rpc_part_create_in_t		args_in;
	rpc_part_create_out_t		args_out;

	if (!part_path)
		part_path = "";  // part_path is an optional arg
	strncpy(args_in.name, part_name, sizeof(args_in.name));
	strncpy(args_in.path, part_path, sizeof(args_in.path));
	args_in.cont_handles = cont->handles;

	return dsos_rpc_part_create(&args_in, &args_out);
}

dsos_part_t *dsos_part_find(dsos_t *cont, const char *name)
{
	int				ret;
	dsos_part_t			*part;
	rpc_part_find_in_t		args_in;
	rpc_part_find_out_t		args_out;

	args_in.cont_handles = cont->handles;
	strncpy(args_in.name, name, sizeof(args_in.name));

	ret = dsos_rpc_part_find(&args_in, &args_out);
	if (ret)
		return NULL;

	part = (dsos_part_t *)malloc(sizeof(dsos_part_t));
	if (!part)
		dsos_fatal("out of memory\n");
	part->handles = args_out.handles;

	return part;
}

int dsos_part_state_set(dsos_part_t *part, sos_part_state_t new_state)
{
	rpc_part_set_state_in_t		args_in;
	rpc_part_set_state_out_t	args_out;

	args_in.handles   = part->handles;
	args_in.new_state = new_state;

	return dsos_rpc_part_set_state(&args_in, &args_out);
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
		dsos_debug("iter %p rbt empty\n");

	return obj;
}

static sos_obj_t iter_remove_min(dsos_iter_t *iter)
{
	sos_obj_t	obj;

	obj = iter_rbt_min(iter);
	if (!obj) {
		iter->done = 1;
		iter->last_server = -1;
		return NULL;
	}
	iter->last_server = dsos_obj_server(obj);
	return obj;
}

static int iter_reset(dsos_iter_t *iter)
{
	sos_obj_t	obj;

	/* Ignore the response to any pending prefetch. */
	iter->prefetch_req = NULL;

	/* Clear out the rbt. */
	while (obj = iter_rbt_min(iter))
		sos_obj_put(obj);

	iter->last_server = -1;
	iter->done = 0;
	rbt_init(&iter->rbt, iter_rbn_cmp_fn);

	return 0;
}

static void iter_prefetch_cb(dsos_req_t *req, uint32_t flags, void *ctxt1, void *ctxt2)
{
	dsos_iter_t	*iter = (dsos_iter_t *)ctxt1;
	sos_obj_t	obj   = (sos_obj_t)ctxt2;

	pthread_mutex_lock(&iter->lock);

	dsos_debug("got obj %p/%08lx%08lx iter %p done %d req %p prefetch_req %p status %d from server %d\n",
		   obj, obj->obj_ref.ref.ods, obj->obj_ref.ref.obj,
		   iter, iter->done, req, iter->prefetch_req, req->buf->resp.msg->u.hdr.status,
		   req->server_num);

	if (iter->done) {
		pthread_mutex_unlock(&iter->lock);
		return;
	}
	if (req != iter->prefetch_req) {
		/* This response has been cancelled. Ignore it. */
		dsos_debug("ignoring\n");
		sos_obj_put(obj);
		pthread_mutex_unlock(&iter->lock);
		return;
	}

	switch (req->buf->resp.msg->u.hdr.status) {
	    case 0:
		iter_insert_obj(iter, obj);
		iter->status = 0;
		break;
	    case ENOENT:
		sos_obj_put(obj);
		iter->status = 0;
		break;
	    default:
		sos_obj_put(obj);
		iter->status = req->buf->resp.msg->u.hdr.status;
		break;
	}

	dsos_debug("signalling\n");
	iter->prefetch_req = NULL;
	pthread_cond_signal(&iter->prefetch_complete);
	pthread_mutex_unlock(&iter->lock);
}

static int iter_prefetch(dsos_iter_t *iter, int server_num)
{
	sos_obj_t		obj;
	rpc_iter_step_one_in_t	args_in;

	if (iter->done)
		return 0;

	obj = sos_obj_malloc(iter->schema->sos_schema);
	if (!obj)
		return ENOMEM;
	obj->ctxt = iter->schema;

	args_in.op          = DSOSD_MSG_ITER_OP_NEXT;
	args_in.iter_handle = iter->handles[server_num];
	args_in.sos_obj     = obj;
	args_in.server_num  = server_num;
	args_in.iter        = iter;
	args_in.cb          = iter_prefetch_cb;

	iter->prefetch_req = dsos_rpc_iter_step_one_async(&args_in);
	if (!iter->prefetch_req)
		return 1;

	dsos_debug("from server %d into obj %p iter %p req %p\n",
		   server_num, obj, iter, iter->prefetch_req);

	return 0;
}

dsos_iter_t *dsos_iter_new(dsos_schema_t *schema, sos_attr_t attr)
{
	int			i, ret;
	dsos_iter_t		*iter;
	rpc_iter_new_in_t	args_in;
	rpc_iter_new_out_t	args_out;

	args_in.schema_handles = schema->handles;
	args_in.attr = attr;

	ret = dsos_rpc_iter_new(&args_in, &args_out);
	if (ret)
		return NULL;

	iter = (dsos_iter_t *)malloc(sizeof(dsos_iter_t));
	if (!iter)
		dsos_fatal("out of memory\n");
	iter->handles     = args_out.handles;
	iter->attr        = attr;
	iter->schema      = schema;
	iter->last_op     = DSOSD_MSG_ITER_OP_NONE;
	iter->done        = 0;
	iter->last_server = -1;
	iter->obj_sz      = schema->sos_schema->data->obj_sz + schema->sos_schema->data->array_data_sz;
	pthread_mutex_init(&iter->lock, 0);
	pthread_cond_init(&iter->prefetch_complete, NULL);
	rbt_init(&iter->rbt, iter_rbn_cmp_fn);

	return iter;
}

int dsos_iter_close(dsos_iter_t *iter)
{
	int			i, ret;
	sos_obj_t		obj;
	rpc_iter_close_in_t	args_in;
	rpc_iter_close_out_t	args_out;

	args_in.iter_handles = iter->handles;

	ret = dsos_rpc_iter_close(&args_in, &args_out);

	while (obj = iter_rbt_min(iter))
		sos_obj_put(obj);
	free(iter->handles);
	free(iter);

	return ret;
}

sos_obj_t dsos_iter_begin(dsos_iter_t *iter)
{
	int			i, ret;
	sos_obj_t		obj, *objs;
	rpc_iter_step_all_in_t	args_in;
	rpc_iter_step_all_out_t	args_out;

	/* Allocate g.num_servers SOS objects. */
	objs = malloc(g.num_servers * sizeof(sos_obj_t));
	if (!objs)
		return NULL;
	for (i = 0; i < g.num_servers; ++i) {
		objs[i] = sos_obj_malloc(iter->schema->sos_schema);
		if (!objs[i])
			return NULL;
		objs[i]->ctxt = iter->schema;
	}

	args_in.op           = DSOSD_MSG_ITER_OP_BEGIN;
	args_in.iter_handles = iter->handles;
	args_in.sos_objs     = objs;
	args_in.key          = NULL;

	pthread_mutex_lock(&iter->lock);
	ret = iter_reset(iter);
	pthread_mutex_unlock(&iter->lock);

	ret = ret || dsos_rpc_iter_step_all(&args_in, &args_out);
	if (ret)
		return NULL;

	for (i = 0; i < g.num_servers; ++i) {
		if (args_out.found[i])
			iter_insert_obj(iter, objs[i]);
		else
			sos_obj_put(objs[i]);
	}
	free(args_out.found);
	free(objs);

	pthread_mutex_lock(&iter->lock);
	obj = iter_remove_min(iter);
#ifdef ITER_PREFETCH
	if (obj)
		iter_prefetch(iter, dsos_obj_server(obj));
#endif
	pthread_mutex_unlock(&iter->lock);

	return obj;
}

sos_obj_t dsos_iter_next(dsos_iter_t *iter)
{
	int			ret;
	sos_obj_t		obj;
	rpc_iter_step_one_in_t	args_in;
	rpc_iter_step_one_out_t	args_out;

	pthread_mutex_lock(&iter->lock);

	dsos_debug("iter %p prefetch_req %p\n", iter, iter->prefetch_req);

	if (iter->done) {
		pthread_mutex_unlock(&iter->lock);
		return NULL;
	}

#ifndef ITER_PREFETCH
	assert(iter->last_server != -1);
	iter_prefetch(iter, iter->last_server);
#endif
	/* Wait for the previously prefetched object. */
	while (iter->prefetch_req)
		pthread_cond_wait(&iter->prefetch_complete, &iter->lock);

	if (iter->status) {
		pthread_mutex_unlock(&iter->lock);
		return NULL;
	}

	obj = iter_remove_min(iter);
#ifdef ITER_PREFETCH
	if (obj)
		iter_prefetch(iter, dsos_obj_server(obj));
#endif

	pthread_mutex_unlock(&iter->lock);

	return obj;
}

sos_obj_t dsos_iter_find(dsos_iter_t *iter, sos_key_t key)
{
	int			i, ret;
	sos_obj_t		obj, *objs;
	rpc_iter_step_all_in_t	args_in;
	rpc_iter_step_all_out_t	args_out;

	/* Allocate g.num_servers SOS objects. */
	objs = malloc(g.num_servers * sizeof(sos_obj_t));
	if (!objs)
		return NULL;
	for (i = 0; i < g.num_servers; ++i) {
		objs[i] = sos_obj_malloc(iter->schema->sos_schema);
		if (!objs[i])
			return NULL;
		objs[i]->ctxt = iter->schema;
	}

	args_in.op           = DSOSD_MSG_ITER_OP_FIND;
	args_in.iter_handles = iter->handles;
	args_in.sos_objs     = objs;
	args_in.key          = key;

	pthread_mutex_lock(&iter->lock);
	ret = iter_reset(iter);
	pthread_mutex_unlock(&iter->lock);

	ret = ret || dsos_rpc_iter_step_all(&args_in, &args_out);
	if (ret)
		return NULL;

	for (i = 0; i < g.num_servers; ++i) {
		if (args_out.found[i])
			iter_insert_obj(iter, objs[i]);
		else
			sos_obj_put(objs[i]);
	}
	free(args_out.found);
	free(objs);

	pthread_mutex_lock(&iter->lock);
	obj = iter_remove_min(iter);
	pthread_mutex_unlock(&iter->lock);

	return obj;
}

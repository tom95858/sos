#include "dsos_priv.h"

static void	iter_prefetch_cb(dsos_req_t *req, dsos_iter_t *iter);
static int	iter_rbn_cmp_fn(void *tree_key, void *key);

int dsos_ping(int server_num, struct dsos_ping_stats *stats)
{
	int			ret;
	rpc_ping_in_t		args_in;
	rpc_ping_out_t		args_out;

	args_in.server_num = server_num;

	ret = dsos_rpc_ping(&args_in, &args_out);

	if (!ret && stats) {
		stats->tot_num_connects    = args_out.tot_num_connects;
		stats->tot_num_disconnects = args_out.tot_num_disconnects;
		stats->tot_num_reqs        = args_out.tot_num_reqs;
		stats->num_clients         = args_out.num_clients;
	}

	return ret;
}

int dsos_ping_all(struct dsos_ping_stats **statsp, int debug)
{
	int			i, ret;
	rpc_ping_in_t		args_in;
	rpc_ping_out_t		*args_outp;

	args_in.debug = debug;
	ret = dsos_rpc_ping_all(&args_in, &args_outp);

	if (!ret && statsp) {
		*statsp = (struct dsos_ping_stats *)malloc(sizeof(struct dsos_ping_stats) * g.num_servers);
		for (i = 0; i < g.num_servers; ++i) {
			(*statsp)[i].tot_num_connects    = args_outp[i].tot_num_connects;
			(*statsp)[i].tot_num_disconnects = args_outp[i].tot_num_disconnects;
			(*statsp)[i].tot_num_reqs        = args_outp[i].tot_num_reqs;
			(*statsp)[i].num_clients         = args_outp[i].num_clients;
			(*statsp)[i].nsecs               = args_outp[i].nsecs;
		}
	}
	free(args_outp);

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

int dsos_container_delete(const char *path)
{
	rpc_container_delete_in_t	args_in;
	rpc_container_delete_out_t	args_out;

	strncpy(args_in.path, path, sizeof(args_in.path));

	return dsos_rpc_container_delete(&args_in, &args_out);
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
	iter->handles   = args_out.handles;
	iter->attr      = attr;
	iter->schema    = schema;
	iter->last_op   = DSOSD_MSG_ITER_OP_NONE;
	iter->done      = 0;
	iter->last_srvr = -1;
	iter->cb        = iter_prefetch_cb;
	iter->obj_sz    = schema->sos_schema->data->obj_sz + schema->sos_schema->data->array_data_sz;
	iter->sos_objs  = calloc(g.num_servers, sizeof(sos_obj_t));
	if (!iter->sos_objs)
		return NULL;
	rbt_init(&iter->rbt, iter_rbn_cmp_fn);

	return iter;
}

int dsos_iter_close(dsos_iter_t *iter)
{
	int			i, ret;
	rpc_iter_close_in_t	args_in;
	rpc_iter_close_out_t	args_out;

	args_in.iter_handles = iter->handles;

	ret = dsos_rpc_iter_close(&args_in, &args_out);

	for (i = 0; i < g.num_servers; ++i) {
		if (iter->sos_objs[i])
			sos_obj_put(iter->sos_objs[i]);
	}
	free(iter->sos_objs);
	free(iter->handles);
	free(iter);

	return ret;
}

static int iter_rbn_cmp_fn(void *tree_key, void *key)
{
	return sos_value_cmp((sos_value_t)tree_key, (sos_value_t)key);
}

static void iter_rbt_insert(dsos_iter_t *iter, sos_value_t v, int server_num)
{
	struct iter_rbn	*rbn = calloc(1, sizeof(struct iter_rbn));
	if (!rbn)
		dsos_fatal("out of memory");
	rbn->rbn.key    = (void *)v;
	rbn->server_num = server_num;

	rbt_ins(&iter->rbt, (void *)rbn);

	dsos_debug("iter %p inserted value %ld from server %d\n",
		   iter, v->data->prim.uint64_, server_num);
}

static void iter_insert_obj(dsos_iter_t *iter, int server_num)
{
	iter_rbt_insert(iter,
			sos_value(iter->sos_objs[server_num], iter->attr),
			server_num);
}

static int iter_rbt_min(dsos_iter_t *iter)
{
	int		ret = -1;
	struct iter_rbn	*rbn = (struct iter_rbn *)rbt_min(&iter->rbt);

	if (rbn) {
		ret = rbn->server_num;
		dsos_debug("iter %p min value %ld from server %d\n",
			   iter, ((sos_value_t)rbn->rbn.key)->data->prim.uint64_, ret);
		rbt_del(&iter->rbt, (struct rbn *)rbn);
		sos_value_put(rbn->rbn.key);
		sos_value_free(rbn->rbn.key);
		free(rbn);
	} else
		dsos_debug("iter %p rbt empty\n");

	return ret;
}

static sos_obj_t iter_remove_min(dsos_iter_t *iter)
{
	int		server_num;
	sos_obj_t	sos_obj;

	server_num = iter_rbt_min(iter);
	if (server_num == -1) {
		iter->done = 1;
		return NULL;
	}
	sos_obj = iter->sos_objs[server_num];
	iter->sos_objs[server_num] = NULL;
	iter->last_srvr = server_num;

	return sos_obj;
}

static int iter_reset(dsos_iter_t *iter)
{
	int		i;
	sos_obj_t	sos_obj;

	/* Clear out the rbt. */
	while (iter_rbt_min(iter) >= 0) ;

	/* Ensure we have num_servers sos objects allocated and ready to be filled. */
	for (i = 0; i < g.num_servers; ++i) {
		if (!iter->sos_objs[i])
			iter->sos_objs[i] = sos_obj_malloc(iter->schema->sos_schema);
		if (!iter->sos_objs[i])
			return ENOMEM;
		iter->sos_objs[i]->ctxt = iter->schema;
	}
	iter->done      = 0;
	iter->last_srvr = -1;
	rbt_init(&iter->rbt, iter_rbn_cmp_fn);
	return 0;
}

static void iter_prefetch_cb(dsos_req_t *req, dsos_iter_t *iter)
{
	dsos_debug("iter %p req %p status %d from server %d\n",
		   iter, req, req->resp->u.hdr.status, req->conn->server_id);

	if (iter->done)
		return;

	switch (req->resp->u.hdr.status) {
	    case 0:
		iter_insert_obj(iter, req->conn->server_id);
		iter->status = 0;
		break;
	    case ENOENT:
		iter->status = 0;
		break;
	    default:
		iter->status = req->resp->u.hdr.status;
		break;
	}
	sem_post(&iter->sem);
}

static int iter_prefetch(dsos_iter_t *iter)
{
	int			server_num;
	rpc_iter_step_one_in_t	args_in;

	if (iter->done)
		return 0;

	server_num = iter->last_srvr;

	iter->sos_objs[server_num] = sos_obj_malloc(iter->schema->sos_schema);
	if (!iter->sos_objs[server_num])
		return ENOMEM;
	iter->sos_objs[server_num]->ctxt = iter->schema;

	args_in.op          = DSOSD_MSG_ITER_OP_NEXT;
	args_in.iter_handle = iter->handles[server_num];
	args_in.sos_obj     = iter->sos_objs[server_num];
	args_in.server_num  = server_num;
	args_in.iter        = iter;

	sem_init(&iter->sem, 0, 0);

	dsos_debug("from server %d into sos_obj %p iter %p\n", server_num, args_in.sos_obj, iter);

	return dsos_rpc_iter_step_one_async(&args_in);
}

sos_obj_t dsos_iter_begin(dsos_iter_t *iter)
{
	int			i, ret;
	sos_obj_t		obj;
	rpc_iter_step_all_in_t	args_in;
	rpc_iter_step_all_out_t	args_out;

	args_in.op           = DSOSD_MSG_ITER_OP_BEGIN;
	args_in.iter_handles = iter->handles;
	args_in.sos_objs     = iter->sos_objs;
	args_in.key          = NULL;

	ret = iter_reset(iter);
	ret = ret || dsos_rpc_iter_step_all(&args_in, &args_out);
	if (ret)
		return NULL;

	for (i = 0; i < g.num_servers; ++i) {
		if (args_out.found[i])
			iter_insert_obj(iter, i);
	}
	free(args_out.found);

	obj = iter_remove_min(iter);
	iter_prefetch(iter);
	return obj;
}

sos_obj_t dsos_iter_next(dsos_iter_t *iter)
{
	int			ret, server_num;
	sos_obj_t		obj;
	rpc_iter_step_one_in_t	args_in;
	rpc_iter_step_one_out_t	args_out;

	dsos_debug("iter %p last_srvr %d\n", iter, iter->last_srvr);

	if (iter->done)
		return NULL;

	/* Wait for the previously prefetched object. */
	sem_wait(&iter->sem);

	if (iter->status)
		return NULL;

	obj = iter_remove_min(iter);
	iter_prefetch(iter);
	return obj;
}

sos_obj_t dsos_iter_find(dsos_iter_t *iter, sos_key_t key)
{
	int			i, ret;
	rpc_iter_step_all_in_t	args_in;
	rpc_iter_step_all_out_t	args_out;

	args_in.op           = DSOSD_MSG_ITER_OP_FIND;
	args_in.iter_handles = iter->handles;
	args_in.sos_objs     = iter->sos_objs;
	args_in.key          = key;

	ret = iter_reset(iter);
	ret = ret || dsos_rpc_iter_step_all(&args_in, &args_out);
	if (ret)
		return NULL;

	for (i = 0; i < g.num_servers; ++i) {
		if (args_out.found[i])
			iter_insert_obj(iter, i);
	}
	free(args_out.found);

	return iter_remove_min(iter);
}

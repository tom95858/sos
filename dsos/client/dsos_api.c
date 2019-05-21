#include "dsos_priv.h"

static int iter_rbn_cmp_fn(void *tree_key, void *key);

int dsos_ping(int server_num)
{
	rpc_ping_in_t		args_in;
	rpc_ping_out_t		args_out;

	args_in.server_num = server_num;

	return dsos_rpc_ping(&args_in, &args_out);
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
	cont->handles = NULL;

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
	size_t			key_sz, obj_sz;
	char			*key_data, *obj_data;
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
	sos_obj_data_get(sos_obj, &obj_data, &obj_sz);

	args_in_find.server_num    = server_num;
	args_in_find.cont_handle   = schema->cont->handles[server_num];
	args_in_find.schema_handle = schema->handles[server_num];
	args_in_find.attr          = attr;
	args_in_find.key           = key;
	args_in_find.va            = (uint64_t)obj_data;
	args_in_find.len           = obj_sz;

	ret = dsos_rpc_obj_find(&args_in_find, &args_out_find);
	if (ret)
		return NULL;

	dsos_debug("obj_id %08lx%08lx\n",
		   args_out_find.obj_id.ref.ods, args_out_find.obj_id.ref.obj);

	// XXX Bo: optimize case where the server owning the index also owns the obj.

	args_in_get.cont_handle = schema->cont->handles[args_out_find.obj_id.ref.ods];
	args_in_get.obj_id      = args_out_find.obj_id;
	args_in_get.va          = (uint64_t)obj_data;
	args_in_get.len         = obj_sz;

	ret = dsos_rpc_obj_get(&args_in_get, &args_out_get);
	if (ret)
		return NULL;

	dsos_debug("obj_id %08lx%08lx sos_obj %p\n",
		   args_out_find.obj_id.ref.ods, args_out_find.obj_id.ref.obj, sos_obj);

	return sos_obj;
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
	iter->obj_sz    = schema->sos_schema->data->obj_sz + schema->sos_schema->data->array_data_sz;
	rbt_init(&iter->rbt, iter_rbn_cmp_fn);
	iter->sos_objs = calloc(g.num_servers, sizeof(sos_obj_t));
	if (!iter->sos_objs)
		return NULL;

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
	iter->handles = NULL;
	free(iter);

	return ret;
}

static int iter_rbn_cmp_fn(void *tree_key, void *key)
{
	sos_value_t v1 = (sos_value_t)tree_key;
	sos_value_t v2 = (sos_value_t)tree_key;
	int ret = sos_value_cmp(v1,v2);

	dsos_debug("v1 %ld v2 %ld cmp %d\n",
		   v1->data->prim.uint64_, v2->data->prim.uint64_, ret);

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

	dsos_debug("iter %p inserted value %ld\n", iter, v->data->prim.uint64_);
}

static int iter_rbt_min(dsos_iter_t *iter)
{
	int		ret = -1;
	struct iter_rbn	*rbn = (struct iter_rbn *)rbt_min(&iter->rbt);
	if (rbn) {
		ret = rbn->server_num;
		rbt_del(&iter->rbt, (struct rbn *)rbn);
		sos_value_put(rbn->rbn.key);
		sos_value_free(rbn->rbn.key);
		free(rbn);
	}
	dsos_debug("iter %p server_num %d\n", iter, ret);
	return ret;
}

static void iter_insert_obj(dsos_iter_t *iter, int server_num)
{
	iter_rbt_insert(iter,
			sos_value(iter->sos_objs[server_num], iter->attr),
			server_num);
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

sos_obj_t dsos_iter_begin(dsos_iter_t *iter)
{
	int			i, ret;
	size_t			obj_sz;
	char			*obj_data;
	rpc_iter_step_all_in_t	args_in;
	rpc_iter_step_all_out_t	args_out;

	for (i = 0; i < g.num_servers; ++i) {
		if (iter->sos_objs[i])
			sos_obj_put(iter->sos_objs[i]);
		iter->sos_objs[i] = sos_obj_malloc(iter->schema->sos_schema);
		if (!iter->sos_objs[i])
			return NULL;
	}

	args_in.op           = DSOSD_MSG_ITER_OP_BEGIN;
	args_in.iter_handles = iter->handles;
	args_in.sos_objs     = iter->sos_objs;

	ret = dsos_rpc_iter_step_all(&args_in, &args_out);
	if (ret)
		return NULL;

	for (i = 0; i < g.num_servers; ++i) {
		if (args_out.found[i])
			iter_insert_obj(iter, i);
	}
	free(args_out.found);

	return iter_remove_min(iter);
}

sos_obj_t dsos_iter_next(dsos_iter_t *iter)
{
	int			ret, server_num;
	size_t			obj_sz;
	char			*obj_data;
	rpc_iter_step_one_in_t	args_in;
	rpc_iter_step_one_out_t	args_out;

	dsos_debug("iter %p last_srvr %d\n", iter, iter->last_srvr);

	if (iter->done)
		return NULL;

	server_num = iter->last_srvr;

	iter->sos_objs[server_num] = sos_obj_malloc(iter->schema->sos_schema);
	if (!iter->sos_objs[server_num])
		return NULL;

	args_in.op          = DSOSD_MSG_ITER_OP_NEXT;
	args_in.iter_handle = iter->handles[iter->last_srvr];
	args_in.sos_obj     = iter->sos_objs[server_num];
	args_in.server_num  = server_num;

	ret = dsos_rpc_iter_step_one(&args_in, &args_out);
	if (ret)
		return NULL;

	if (args_out.found)
		iter_insert_obj(iter, server_num);

	return iter_remove_min(iter);
}

#include "dsos_priv.h"

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
	rpc_container_close_in_t	args_in;
	rpc_container_close_out_t	args_out;

	args_in.handles = cont->handles;

	return dsos_rpc_container_close(&args_in, &args_out);
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
	schema->handles = args_out.handles;
	schema->schema  = sos_schema_from_template(template);
	schema->cont    = cont;

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
	schema->handles = args_out.handles;
	schema->schema  = sos_schema_from_template(t);

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

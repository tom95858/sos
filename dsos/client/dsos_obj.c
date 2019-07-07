#include "dsos_priv.h"

int dsos_obj_server(sos_obj_t obj)
{
	return obj->obj_ref.ref.ods;
}

sos_obj_t dsos_obj_alloc(dsos_schema_t *schema)
{
	sos_obj_t obj = sos_obj_malloc(schema->sos_schema);
	if (obj)
		obj->ctxt = schema;
	return obj;
}

int dsos_obj_create(sos_obj_t obj, dsos_obj_cb_t cb, void *ctxt)
{
	rpc_object_create_in_t	args_in;

	args_in.schema = (dsos_schema_t *)obj->ctxt;
	args_in.obj    = obj;
	args_in.cb     = cb;
	args_in.ctxt   = ctxt;

	sos_obj_get(obj);  // this ref is dropped in obj_create_cb()

	return dsos_rpc_object_create(&args_in);
}

sos_obj_t dsos_obj_get(dsos_schema_t *schema, sos_obj_ref_t ref)
{
	int			ret;
	sos_obj_t		obj;
	rpc_obj_get_in_t	args_in;
	rpc_obj_get_out_t	args_out;

	obj = sos_obj_malloc(schema->sos_schema);
	if (!obj)
		return NULL;
	obj->ctxt = schema;

	args_in.sos_obj = obj;
	args_in.cont    = schema->cont;
	args_in.obj_id  = ref;

	ret = dsos_rpc_obj_get(&args_in, &args_out);
	if (ret)
		return NULL;
	return args_in.sos_obj;
}

int dsos_obj_delete(sos_obj_t obj)
{
	int			ret;
	rpc_object_delete_in_t	args_in;
	rpc_object_delete_out_t args_out;

	args_in.obj = obj;

	ret = dsos_rpc_object_delete(&args_in, &args_out);

	sos_obj_put(obj);

	return ret;
}

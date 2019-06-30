#include "dsos_priv.h"

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

	return dsos_rpc_object_create(&args_in);
}

int dsos_obj_delete(sos_obj_t obj)
{
	int			ret;
	rpc_object_delete_in_t	args_in;

	args_in.obj = obj;

	ret = dsos_rpc_object_delete(&args_in);

	sos_obj_put(obj);

	return ret;
}

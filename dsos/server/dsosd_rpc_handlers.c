#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include "dsosd_priv.h"

static char *handle_type_str[] = {
	[DSOSD_HANDLE_CONT]   = "cont",
	[DSOSD_HANDLE_PART]   = "part",
	[DSOSD_HANDLE_SCHEMA] = "schema",
	[DSOSD_HANDLE_ITER]   = "iter",
	[DSOSD_HANDLE_FILTER] = "filter",
	[DSOSD_HANDLE_INDEX]  = "index"
};

const char *dsosd_handle_type_str(dsosd_handle_type_t type)
{
	return handle_type_str[type];
}

dsos_handle_t dsosd_ptr_to_handle(dsosd_rpc_t *rpc, void *ptr, dsosd_handle_type_t type)
{
	struct ptr_rbn	*rbn;
	dsosd_client_t	*client = rpc->client;
	dsos_handle_t	handle = client->next_handle++;

	rbn = calloc(1, sizeof(struct ptr_rbn));
	if (!rbn)
		dsosd_fatal("out of memory\n");
	rbn_init((struct rbn *)rbn, (void *)handle);
	rbn->ptr  = ptr;
	rbn->type = type;
	rbt_ins(&client->handle_rbt, (void *)rbn);
	dsosd_debug("client %p ptr %p assigned handle 0x%lx %s\n",
		    client, ptr, handle, dsosd_handle_type_str(type));

	return handle;
}

void *dsosd_handle_to_ptr(dsosd_rpc_t *rpc, dsos_handle_t handle, dsosd_handle_type_t want_type)
{
	struct ptr_rbn	*rbn;
	dsosd_client_t	*client = rpc->client;

	rbn = (struct ptr_rbn *)rbt_find(&client->handle_rbt, (void *)handle);
	if (!rbn) {
		dsosd_error("client %p handle 0x%lx not found\n", client, handle);
		return NULL;
	}
	if (rbn->type != want_type) {
		dsosd_error("client %p handle 0x%lx is ptr %d %s want %s\n",
			    client, handle, rbn->ptr,
			    dsosd_handle_type_str(rbn->type),
			    dsosd_handle_type_str(want_type));
		return NULL;
	}
	dsosd_debug("client %p handle 0x%lx is ptr %p %s\n",
		    client, handle, rbn->ptr, dsosd_handle_type_str(rbn->type));
	return rbn->ptr;
}

void *dsosd_rpc_unpack_handle_to_ptr(dsosd_rpc_t *rpc, dsosd_handle_type_t want_type)
{
	dsos_handle_t handle = dsosd_rpc_unpack_handle(rpc);
	return dsosd_handle_to_ptr(rpc, handle, want_type);
}

void dsosd_handle_free(dsosd_rpc_t *rpc, dsos_handle_t handle)
{
	struct ptr_rbn	*rbn;
	dsosd_client_t	*client = rpc->client;

	rbn = (struct ptr_rbn *)rbt_find(&client->handle_rbt, (void *)handle);
	if (rbn) {
		rbt_del(&client->handle_rbt, (struct rbn *)rbn);
		free(rbn);
	} else
		dsosd_error("client %p handle 0x%lx not found\n", client, handle);
}

void rpc_handle_ping(dsosd_rpc_t *rpc)
{
	struct dsos_ping_stats	stats = {
		.tot_num_connects           = g.stats.tot_num_connects,
		.tot_num_disconnects        = g.stats.tot_num_disconnects,
		.tot_num_reqs               = g.stats.tot_num_reqs,
		.tot_num_obj_creates_inline = g.stats.tot_num_obj_creates_inline,
		.tot_num_obj_creates_rma    = g.stats.tot_num_obj_creates_rma,
		.tot_num_obj_gets_inline    = g.stats.tot_num_obj_gets_inline,
		.tot_num_obj_gets_rma       = g.stats.tot_num_obj_gets_rma,
		.num_clients                = g.num_clients,
		.nsecs                      = 0,
	};

	dsosd_debug("rpc %p\n", rpc);
	dsos_pack_buf(&rpc->resp, &stats, sizeof(stats));
	dsosd_rpc_complete(rpc, 0);
}

void rpc_handle_obj_create(dsosd_rpc_t *rpc)
{
	int		ret;
	uint64_t	remote_va, remote_len;
	char		*obj_data;
	size_t		obj_sz;
	uint32_t	flags;
	zap_err_t	zerr;
	sos_schema_t	schema;
	sos_obj_t	obj;
	sos_obj_ref_t	obj_id;
	dsosd_client_t	*client = rpc->client;

	schema = dsosd_rpc_unpack_handle_to_ptr(rpc, DSOSD_HANDLE_SCHEMA);
	flags  = dsosd_rpc_unpack_u32(rpc);

	if (!schema) {
		dsosd_rpc_complete(rpc, EBADF);
		return;
	}

	obj = sos_obj_new(schema);
	if (!obj) {
		dsosd_error("error %d creating obj\n", errno);
		dsosd_rpc_complete(rpc, ENOMEM);
		return;
	}
	sos_obj_data_get(obj, &obj_data, &obj_sz);

	/*
	 * A DSOS object id is unique within a distributed container. The top
	 * uint32_t identifies the server where the object resides, and the
	 * bottom uint32_t is the object ref which identifies the object within
	 * its container on that server. This overlays the original (local) SOS
	 * obj id of the same size; it overloads the ODS ref part to store
	 * the server ref. The ODS ref is not needed because it is now
	 * implied from the container, and from the assumption that the container
	 * in DSOS has only one partition.
	 */
	obj_id = obj->obj_ref;
	obj_id.ref.ods = g.opts.server_num;
	dsosd_rpc_pack_obj_id(rpc, obj_id);

	if (flags & DSOS_RPC_FLAGS_INLINE) {
		/* The object data is in the recv buffer. Copy it to the object. */
		dsosd_rpc_unpack_obj(rpc, obj);
		*(uint64_t *)obj_data = sos_schema_id(schema);
		ret = sos_obj_index(obj);
		if (ret)
			dsosd_error("ep %p sos_obj_index ret %d\n", client->ep, ret);
		sos_obj_put(obj);
		++g.stats.tot_num_obj_creates_inline;
		dsosd_debug("rpc %p new inline obj %p obj_data %p sz %d id %08lx%08lx\n", rpc,
			    obj, obj_data, obj_sz, obj_id.ref.ods, obj_id.ref.obj);
		dsosd_rpc_complete(rpc, 0);
	} else {
		/* RMA-read the object from client memory. */
		remote_va = dsosd_rpc_unpack_obj_ptr(rpc, &remote_len);
		assert(remote_len == obj_sz);
		rpc->ctxt = obj;
#if 1
		/*
		 * We RMA into rpc->rma_buf for the moment. Once SOS
		 * is enhanced to map object memory, the server can
		 * RMA-read it directly. Until then, we RMA into a
		 * scratch buffer and then memcpy into the object from
		 * that in the completion handler.
		 */
		rpc->rma_len = remote_len;
		rpc->rma_buf = mm_alloc(client->heap, remote_len);
		if (!rpc->rma_buf)
			dsosd_fatal("could not alloc from shared heap\n");
		dsosd_debug("rpc %p new obj %p: %p/%d rma_buf %p va %p id %08lx%08lx\n", rpc,
			    obj, obj_data, obj_sz, rpc->rma_buf, remote_va,
			    obj_id.ref.ods, obj_id.ref.obj);
		zerr = zap_read(client->ep,
				client->rmap, (char *)remote_va,	/* src */
				client->lmap, rpc->rma_buf,		/* dst */
				obj_sz, rpc);
#endif
		if (zerr) {
			dsosd_error("zap_read ep %p zerr %d %s\n",
				    rpc->client->ep, zerr, zap_err_str(zerr));
			dsosd_rpc_complete(rpc, zerr);
			sos_obj_put(obj);
		}
	}
}

void rpc_handle_obj_delete(dsosd_rpc_t *rpc)
{
	int		ret;
	sos_t		cont;
	sos_part_t	part;
	sos_obj_t	obj;
	sos_obj_ref_t	obj_ref;

	cont = dsosd_rpc_unpack_handle_to_ptr(rpc, DSOSD_HANDLE_CONT);
	if (!cont) {
		ret = EBADF;
		goto out;
	}

	/*
	 * Re-create the local object reference from the DSOS reference.
	 */
	obj_ref = dsosd_rpc_unpack_obj_id(rpc);
	part = sos_part_find(cont, "ROOT");
	if (!part) {
		ret = EBADFD;
		goto out;
	}
	obj_ref.ref.ods = sos_part_id(part);
	sos_part_put(part);

	obj = sos_ref_as_obj(cont, obj_ref);
	if (!obj) {
		ret = ENOENT;
		goto out;
	}
	sos_obj_remove(obj);
	sos_obj_delete(obj);
	sos_obj_put(obj);
	ret = 0;
 out:
	dsosd_debug("rpc %p: cont %p part %p obj %p %08lx%08lx status %d\n", rpc,
		    cont, part, obj, obj_ref.ref.ods, obj_ref.ref.obj, ret);

	dsosd_rpc_complete(rpc, ret);
}

/* Replace the first occurrence of %% with the server number. */
static void rewrite_path(char *path)
{
	char	buf[4], *p;

	p = strstr(path, "%%");
	if (p) {
		snprintf(buf, sizeof(buf), "%02d", g.opts.server_num);
		strncpy(p, buf, 2);
	}
}

void rpc_handle_cont_new(dsosd_rpc_t *rpc)
{
	int	mode, ret;
	char	*path;

	mode = dsosd_rpc_unpack_u32(rpc);
	path = dsosd_rpc_unpack_str(rpc);

	rewrite_path(path);

	ret = sos_container_new(path, mode);

	dsosd_debug("rpc %p: '%s' perms 0%o, ret %d\n", rpc, path, mode, ret);

	dsosd_rpc_complete(rpc, ret);
}

void rpc_handle_cont_open(dsosd_rpc_t *rpc)
{
	int	perms, ret = 0;
	char	*path;
	sos_t	cont;

	perms = dsosd_rpc_unpack_u32(rpc);
	path  = dsosd_rpc_unpack_str(rpc);

	rewrite_path(path);

	cont = sos_container_open(path, perms);
	if (cont)
		dsosd_rpc_pack_handle(rpc, dsosd_ptr_to_handle(rpc, cont, DSOSD_HANDLE_CONT));
	else
		ret = ENOENT;

	dsosd_debug("rpc %p: '%s' perms 0%o, cont %p\n", rpc, path, perms, cont);

	dsosd_rpc_complete(rpc, ret);
}

void rpc_handle_cont_close(dsosd_rpc_t *rpc)
{
	dsos_handle_t		handle;
	sos_t			cont;
	struct ptr_rbn		*rbn;
	sos_commit_t		flags;

	handle = dsosd_rpc_unpack_handle(rpc);
	flags  = dsosd_rpc_unpack_u32(rpc);

	cont = (sos_t)dsosd_handle_to_ptr(rpc, handle, DSOSD_HANDLE_CONT);
	if (!cont) {
		dsosd_rpc_complete(rpc, EBADF);
		return;
	}

	dsosd_debug("rpc %p: cont %lx/%p flags %d\n", rpc, handle, cont, flags);

	/* Close all indices the client has open in the container being closed. */
	while ((rbn = (struct ptr_rbn *)rbt_min(&rpc->client->idx_rbt))) {
		sos_index_t idx = (sos_index_t)rbn->ptr;
		if (idx->sos == cont) {
			dsosd_debug("closing idx %p\n", idx);
			rbt_del(&rpc->client->idx_rbt, (struct rbn *)rbn);
			sos_index_close((sos_index_t)rbn->ptr, SOS_COMMIT_ASYNC);
			free(rbn->rbn.key);
		}
	}

	sos_container_close(cont, flags);
	dsosd_handle_free(rpc, handle);

	dsosd_rpc_complete(rpc, 0);
}

void rpc_handle_schema_by_name(dsosd_rpc_t *rpc)
{
	int		ret = 0;
	char		*schema_name;
	dsos_handle_t	schema_handle;
	sos_t		cont;
	sos_schema_t	schema;

	cont        = dsosd_rpc_unpack_handle_to_ptr(rpc, DSOSD_HANDLE_CONT);
	schema_name = dsosd_rpc_unpack_str(rpc);

	if (!cont) {
		ret = EBADF;
		goto out;
	}

	schema = sos_schema_by_name(cont, schema_name);
	if (schema) {
		schema_handle = dsosd_ptr_to_handle(rpc, schema, DSOSD_HANDLE_SCHEMA);
		dsosd_rpc_pack_handle(rpc, schema_handle);
		dsosd_rpc_pack_schema(rpc, schema);
	} else {
		ret = ENOENT;
	}
 out:
	dsosd_debug("rpc %p: cont %p schema %lx/%p status %d\n", rpc,
		    cont, schema_handle, schema, ret);
	dsosd_rpc_complete(rpc, ret);
}

void rpc_handle_schema_by_id(dsosd_rpc_t *rpc)
{
	int		ret = 0, schema_id;
	dsos_handle_t	schema_handle;
	sos_t		cont;
	sos_schema_t	schema;

	cont      = dsosd_rpc_unpack_handle_to_ptr(rpc, DSOSD_HANDLE_CONT);
	schema_id = dsosd_rpc_unpack_u32(rpc);

	if (!cont) {
		ret = EBADF;
		goto out;
	}

	schema = sos_schema_by_id(cont, schema_id);
	if (schema) {
		schema_handle = dsosd_ptr_to_handle(rpc, schema, DSOSD_HANDLE_SCHEMA);
		dsosd_rpc_pack_handle(rpc, schema_handle);
		dsosd_rpc_pack_schema(rpc, schema);
	} else {
		ret = ENOENT;
	}
 out:
	dsosd_debug("rpc %p: schema_id %d cont %p schema %lx/%p status %d\n", rpc,
		    schema_id, cont, schema_handle, schema, ret);
	dsosd_rpc_complete(rpc, ret);
}

void rpc_handle_schema_first(dsosd_rpc_t *rpc)
{
	int		ret = 0;
	dsos_handle_t	schema_handle;
	sos_t		cont;
	sos_schema_t	schema = NULL;

	cont = dsosd_rpc_unpack_handle_to_ptr(rpc, DSOSD_HANDLE_CONT);
	if (!cont) {
		ret = EBADF;
		goto out;
	}

	schema = sos_schema_first(cont);
	if (schema) {
		schema_handle = dsosd_ptr_to_handle(rpc, schema, DSOSD_HANDLE_SCHEMA);
		dsosd_rpc_pack_handle(rpc, schema_handle);
		dsosd_rpc_pack_schema(rpc, schema);
	} else {
		ret = ENOENT;
	}
 out:
	dsosd_debug("rpc %p: cont %p schema %lx/%p status %d\n", rpc,
		    cont, schema_handle, schema, ret);
	dsosd_rpc_complete(rpc, ret);
}

void rpc_handle_schema_next(dsosd_rpc_t *rpc)
{
	int		ret = 0;
	dsos_handle_t	next_schema_handle;
	sos_schema_t	next_schema = NULL, schema;

	schema = dsosd_rpc_unpack_handle_to_ptr(rpc, DSOSD_HANDLE_SCHEMA);
	if (!schema) {
		ret = EBADF;
		goto out;
	}

	next_schema = sos_schema_next(schema);
	if (next_schema) {
		next_schema_handle = dsosd_ptr_to_handle(rpc, next_schema, DSOSD_HANDLE_SCHEMA);
		dsosd_rpc_pack_handle(rpc, next_schema_handle);
		dsosd_rpc_pack_schema(rpc, next_schema);
	} else {
		ret = ENOENT;
	}
 out:
	dsosd_debug("rpc %p: schema %p next_schema %lx/%p status %d\n", rpc,
		    schema, next_schema_handle, next_schema, ret);
	dsosd_rpc_complete(rpc, ret);
}

void rpc_handle_schema_add(dsosd_rpc_t *rpc)
{
	int		ret;
	dsos_handle_t	schema_handle;
	sos_t		cont;
	sos_schema_t	schema;

	cont   = dsosd_rpc_unpack_handle_to_ptr(rpc, DSOSD_HANDLE_CONT);
	schema = dsosd_rpc_unpack_schema(rpc);

	if (!cont || !schema) {
		ret = EBADF;
	} else {
		ret = sos_schema_add(cont, schema);
		schema_handle = dsosd_ptr_to_handle(rpc, schema, DSOSD_HANDLE_SCHEMA);
		dsosd_rpc_pack_handle(rpc, schema_handle);
	}

	dsosd_debug("rpc %p: cont %p schema %p/%p\n",
		    rpc, cont, schema_handle, schema);

	dsosd_rpc_complete(rpc, ret);
}

void rpc_handle_part_create(dsosd_rpc_t *rpc)
{
	int		ret;
	char		*name, *path;
	sos_schema_t	schema;
	sos_t		cont;

	cont = dsosd_rpc_unpack_handle_to_ptr(rpc, DSOSD_HANDLE_CONT);
	name = dsosd_rpc_unpack_str(rpc);
	path = dsosd_rpc_unpack_str(rpc);

	if (!cont) {
		ret = EBADF;
		goto out;
	}

	ret = sos_part_create(cont, name, path);
 out:
	dsosd_debug("rpc %p: cont %p name %s path %s ret %d\n",
		    rpc, cont, name, path, ret);
	dsosd_rpc_complete(rpc, ret);
}

void rpc_handle_part_find(dsosd_rpc_t *rpc)
{
	int		ret = 0;
	char		*name, *path;
	sos_t		cont;
	sos_part_t	part;

	cont = dsosd_rpc_unpack_handle_to_ptr(rpc, DSOSD_HANDLE_CONT);
	name = dsosd_rpc_unpack_str(rpc);

	if (!cont) {
		ret = EBADF;
		goto out;
	}

	part = sos_part_find(cont, name);
	if (part)
		dsosd_rpc_pack_handle(rpc, dsosd_ptr_to_handle(rpc, part, DSOSD_HANDLE_PART));
	else
		ret = ENOENT;
 out:
	dsosd_debug("rpc %p: cont %p name %s part %p ret %d\n",
		    rpc, cont, name, part, ret);
	dsosd_rpc_complete(rpc, ret);
}

void rpc_handle_part_set_state(dsosd_rpc_t *rpc)
{
	int		state, ret;
	sos_part_t	part;
	dsos_handle_t	handle;

	state  = dsosd_rpc_unpack_u32(rpc);
	handle = dsosd_rpc_unpack_handle(rpc);

	part = (sos_part_t)dsosd_handle_to_ptr(rpc, handle, DSOSD_HANDLE_PART);
	if (!part) {
		ret = EBADF;
		goto out;
	}

	ret = sos_part_state_set(part, state);

	/*
	 * The part object is unavailable after this. This is for ease of use
	 * in the common case where we create a partition, set its state,
	 * then begin using the container.
	 */
	sos_part_put(part);
	dsosd_handle_free(rpc, handle);
 out:
	dsosd_debug("rpc %p: part %lx/%p state %d\n", rpc, handle, part, state);
	dsosd_rpc_complete(rpc, ret);
}

void rpc_handle_schema_from_template(dsosd_rpc_t *rpc)
{
	int		ret = 0;
	sos_schema_t	schema;

	schema = dsosd_rpc_unpack_schema(rpc);
	if (schema)
		dsosd_rpc_pack_handle(rpc, dsosd_ptr_to_handle(rpc, schema, DSOSD_HANDLE_SCHEMA));
	else
		ret = EINVAL;
 out:
	dsosd_debug("rpc %p: schema %p ret %d\n", rpc, schema, ret);
	dsosd_rpc_complete(rpc, ret);
}

void rpc_handle_obj_get(dsosd_rpc_t *rpc)
{
	int		ret = ENOENT;
	sos_t		cont;
	sos_obj_t	obj = NULL;
	sos_part_t	primary;
	uint64_t	obj_remote_va;
	uint64_t	obj_remote_len;
	sos_obj_ref_t	obj_id;

	cont          = dsosd_rpc_unpack_handle_to_ptr(rpc, DSOSD_HANDLE_CONT);
	obj_id        = dsosd_rpc_unpack_obj_id(rpc);
	obj_remote_va = dsosd_rpc_unpack_obj_ptr(rpc, &obj_remote_len);

	if (!cont) {
		ret = EBADF;
		goto out;
	}

	/* Use the ODS from the primary partition in the given container. */
	primary = __sos_primary_obj_part(cont);
	if (!primary) {
		ret = ENOENT;
		goto out;
	}
	obj_id.ref.ods = sos_part_id(primary);

	obj = sos_ref_as_obj(cont, obj_id);

	dsosd_debug("rpc %p obj_id %08lx%08lx obj %p va %p len %d\n",
		    rpc, obj_id.ref.ods, obj_id.ref.obj,
		    obj, obj_remote_va, obj_remote_len);
 out:
	if (obj)
		dsosd_rpc_complete_with_obj(rpc, obj, obj_remote_va);
	else
		dsosd_rpc_complete(rpc, ret);
}

void rpc_handle_iter_close(dsosd_rpc_t *rpc)
{
	int		ret = 0;
	sos_iter_t	iter;
	dsos_handle_t	handle;

	handle = dsosd_rpc_unpack_handle(rpc);

	iter = (sos_iter_t)dsosd_handle_to_ptr(rpc, handle, DSOSD_HANDLE_ITER);
	if (!iter) {
		ret = EBADF;
		goto out;
	}

	sos_iter_free(iter);

	dsosd_handle_free(rpc, handle);

	dsosd_debug("rpc %p: iter %lx/%p ret %d\n", rpc, handle, iter, ret);
 out:
	dsosd_rpc_complete(rpc, ret);
}

void rpc_handle_iter_new(dsosd_rpc_t *rpc)
{
	int		ret = 0;
	uint32_t	attr_id;
	sos_schema_t	schema;
	sos_attr_t	attr;
	sos_iter_t	iter;

	attr_id = dsosd_rpc_unpack_u32(rpc);
	schema  = dsosd_rpc_unpack_handle_to_ptr(rpc, DSOSD_HANDLE_SCHEMA);

	if (!schema) {
		ret = EBADF;
		goto out;
	}

	attr = sos_schema_attr_by_id(schema, attr_id);
	if (!attr) {
		ret = EBADF;
		goto out;
	}

	iter = sos_attr_iter_new(attr);
	if (iter)
		dsosd_rpc_pack_handle(rpc, dsosd_ptr_to_handle(rpc, iter, DSOSD_HANDLE_ITER));
	else
		ret = ENOENT;

	dsosd_debug("rpc %p: schema %p attr %p iter %p ret %d\n",
		    rpc, schema, attr, iter, ret);
 out:
	dsosd_rpc_complete(rpc, ret);
}

void rpc_handle_iter_step(dsosd_rpc_t *rpc)
{
	int		op, ret = 0;
	uint64_t	obj_va;
	uint64_t	obj_sz;
	sos_key_t	key = NULL;
	sos_iter_t	iter;
	sos_obj_t	obj = NULL;

	op     = dsosd_rpc_unpack_u32(rpc);
	iter   = dsosd_rpc_unpack_handle_to_ptr(rpc, DSOSD_HANDLE_ITER);
	obj_va = dsosd_rpc_unpack_obj_ptr(rpc, &obj_sz);
	key    = dsosd_rpc_unpack_key(rpc);

	if (!iter) {
		ret = EBADF;
		goto out;
	}

	switch (op) {
	    case DSOS_RPC_ITER_OP_BEGIN:
		ret = sos_iter_begin(iter);
		break;
	    case DSOS_RPC_ITER_OP_NEXT:
		ret = sos_iter_next(iter);
		break;
	    case DSOS_RPC_ITER_OP_FIND:
		ret = sos_iter_find(iter, key);
		break;
	    default:
		ret = EINVAL;
		break;
	}
	if (!ret) {
		obj = sos_iter_obj(iter);
		if (!obj)
			ret = ENOENT;
	}
	dsosd_debug("rpc %p: op %d iter %p obj %p obj_va %lx obj_sz %ld key %p ret %d\n",
		    rpc, op, iter, obj, obj_va, obj_sz, key, ret);
 out:
	if (obj)
		dsosd_rpc_complete_with_obj(rpc, obj, obj_va);
	else
		dsosd_rpc_complete(rpc, ret);
	if (key)
		sos_key_put(key);
}

void rpc_handle_filter_step(dsosd_rpc_t *rpc)
{
	int		op, ret = 0;
	uint64_t	obj_va;
	uint64_t	obj_sz;
	sos_filter_t	filter;
	sos_obj_t	obj = NULL;

	op     = dsosd_rpc_unpack_u32(rpc);
	filter = dsosd_rpc_unpack_handle_to_ptr(rpc, DSOSD_HANDLE_FILTER);
	obj_va = dsosd_rpc_unpack_obj_ptr(rpc, &obj_sz);

	if (!filter) {
		ret = EBADF;
		goto out;
	}

	switch (op) {
	    case DSOS_RPC_FILTER_OP_BEGIN:
		obj = sos_filter_begin(filter);
		break;
	    case DSOS_RPC_FILTER_OP_NEXT:
		obj = sos_filter_next(filter);
		break;
	}
	if (!obj)
		ret = ENOENT;

	dsosd_debug("rpc %p: op %d filter %p obj %p obj_va %lx obj_sz %ld ret %d\n",
		    rpc, op, filter, obj, obj_va, obj_sz, ret);
 out:
	if (obj)
		dsosd_rpc_complete_with_obj(rpc, obj, obj_va);
	else
		dsosd_rpc_complete(rpc, ret);
}

void rpc_handle_filter_new(dsosd_rpc_t *rpc)
{
	int		ret = 0;
	sos_iter_t	iter;
	sos_filter_t	filter;

	iter = dsosd_rpc_unpack_handle_to_ptr(rpc, DSOSD_HANDLE_ITER);
	if (!iter) {
		ret = EBADF;
		goto out;
	}

	filter = sos_filter_new(iter);
	if (filter)
		dsosd_rpc_pack_handle(rpc, dsosd_ptr_to_handle(rpc, filter, DSOSD_HANDLE_FILTER));
	else
		ret = ENOENT;

	dsosd_debug("rpc %p: iter %p filter %p ret %d\n", rpc, iter, filter, ret);
 out:
	dsosd_rpc_complete(rpc, ret);
}

void rpc_handle_filter_free(dsosd_rpc_t *rpc)
{
	dsos_handle_t	handle;
	sos_filter_t	filter;

	handle = dsosd_rpc_unpack_handle(rpc);

	filter = (sos_filter_t)dsosd_handle_to_ptr(rpc, handle, DSOSD_HANDLE_FILTER);
	if (!filter) {
		dsosd_rpc_complete(rpc, EBADF);
		return;
	}

	dsosd_debug("rpc %p: filter %p\n", rpc, filter);

	sos_filter_free(filter);
	dsosd_handle_free(rpc, handle);

	dsosd_rpc_complete(rpc, 0);
}

void rpc_handle_filter_miss_count(dsosd_rpc_t *rpc)
{
	sos_filter_t	filter;

	filter = dsosd_rpc_unpack_handle_to_ptr(rpc, DSOSD_HANDLE_FILTER);
	if (!filter) {
		dsosd_rpc_complete(rpc, EBADF);
		return;
	}

	dsosd_debug("rpc %p: filter %p\n", rpc, filter);

	dsosd_rpc_pack_u32(rpc, sos_filter_miss_count(filter));

	dsosd_rpc_complete(rpc, 0);
}

void rpc_handle_filter_flags_get(dsosd_rpc_t *rpc)
{
	sos_filter_t	filter;

	filter = dsosd_rpc_unpack_handle_to_ptr(rpc, DSOSD_HANDLE_FILTER);
	if (!filter) {
		dsosd_rpc_complete(rpc, EBADF);
		return;
	}

	dsosd_debug("rpc %p: filter %p\n", rpc, filter);

	dsosd_rpc_pack_u32(rpc, sos_filter_flags_get(filter));

	dsosd_rpc_complete(rpc, 0);
}

void rpc_handle_filter_flags_set(dsosd_rpc_t *rpc)
{
	sos_iter_flags_t	flags;
	sos_filter_t		filter;

	filter = dsosd_rpc_unpack_handle_to_ptr(rpc, DSOSD_HANDLE_FILTER);
	flags  = dsosd_rpc_unpack_u32(rpc);
	if (!filter) {
		dsosd_rpc_complete(rpc, EBADF);
		return;
	}

	sos_filter_flags_set(filter, flags);

	dsosd_debug("rpc %p: filter %p flags %d\n", rpc, filter, flags);

	dsosd_rpc_complete(rpc, 0);
}

void rpc_handle_filter_cond_add(dsosd_rpc_t *rpc)
{
	int			ret;
	sos_attr_t		attr;
	sos_value_t		value;
	sos_cond_t		cond;
	sos_iter_flags_t	flags;
	sos_filter_t		filter;

	filter = dsosd_rpc_unpack_handle_to_ptr(rpc, DSOSD_HANDLE_FILTER);
	attr   = dsosd_rpc_unpack_attr(rpc);
	cond   = dsosd_rpc_unpack_u32(rpc);
	value  = dsosd_rpc_unpack_value(rpc);
	if (!filter) {
		dsosd_rpc_complete(rpc, EBADF);
		return;
	}

	ret = sos_filter_cond_add(filter, attr, cond, value);

	char *str = malloc(16);
	sos_value_to_str(value, str, 16);
	dsosd_debug("rpc %p: filter %p attr %p cond %d value %s ret %d\n",
		    rpc, filter, attr, cond, str, ret);
	free(str);

	dsosd_rpc_complete(rpc, ret);

	sos_value_put(value);
	sos_value_free(value);
}

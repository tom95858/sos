#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "dsosd_priv.h"

dsosd_rpc_t *dsosd_rpc_new(dsosd_client_t *client, dsos_msg_t *msg, size_t len)
{
	dsosd_rpc_t	*rpc;

	rpc = (dsosd_rpc_t *)dsosd_malloc(sizeof(dsosd_rpc_t));

	rpc->refcount = 1;  // start with a reference
	rpc->client   = client;
	rpc->ctxt     = NULL;

	rpc->req.free_fn = NULL;
	rpc->req.len     = len;
	rpc->req.max_len = len;
	rpc->req.msg     = msg;
	rpc->req.p       = (char *)(rpc->req.msg + 1);

	rpc->resp.free_fn = free;
	rpc->resp.len     = sizeof(dsos_msg_t);
	rpc->resp.max_len = zap_max_msg(g.zap);
	rpc->resp.msg     = (dsos_msg_t *)dsosd_malloc(rpc->resp.max_len);
	rpc->resp.p       = (char *)(rpc->resp.msg + 1);

	rpc->resp.msg->hdr.type   = msg->hdr.type;
	rpc->resp.msg->hdr.id     = msg->hdr.id;
	rpc->resp.msg->hdr.status = 0;
	rpc->resp.msg->hdr.flags  = 0;

	dsosd_client_get(client);

	dsosd_rpc_debug("new rpc %p for %s ep %p msg %p id %ld len %d\n",
			rpc, dsos_rpc_type_to_str(msg->hdr.type), client->ep,
			msg, msg->hdr.id, len);
#ifdef RPC_DEBUG
	{
	char *s;

	asprintf(&s, "Response from client %p:", client);
	dsos_buf_dump(stdout, &rpc->req, s);
	free(s);
	}
#endif
	return rpc;
}

void dsosd_rpc_complete_with_obj(dsosd_rpc_t *rpc, sos_obj_t obj, uint64_t obj_remote_va)
{
	zap_err_t	zerr;
	char		*obj_data;
	size_t		obj_sz;
	sos_obj_ref_t	obj_id;
	dsosd_client_t	*client = rpc->client;

	sos_obj_data_get(obj, &obj_data, &obj_sz);

	obj_id = obj->obj_ref;
	obj_id.ref.ods = g.opts.server_num;
	dsosd_rpc_pack_obj_id(rpc, obj_id);

	if (dsosd_rpc_pack_fits(rpc, dsos_pack_obj_needs(obj) + sizeof(uint32_t))) {
		/* Send object in-line within the response msg. */
		dsosd_rpc_pack_u32(rpc, DSOS_RPC_FLAGS_INLINE);
		dsosd_rpc_pack_obj(rpc, obj);
		sos_obj_put(obj);
		++g.stats.tot_num_obj_gets_inline;
		dsosd_rpc_debug("rpc %p inline obj %p obj_data %p sz %d\n", rpc, obj, obj_data, obj_sz);
		dsosd_rpc_complete(rpc, 0);
	} else {
		/* RMA-write the object to the client's buffer. */
		dsosd_rpc_pack_u32(rpc, 0);
#if 1
		/*
		 * We RMA from rpc->rma_buf for the moment. Once SOS
		 * is enhanced to register the ODS maps, can RMA-write
		 * to the client directly from the object. Until then,
		 * we copy into a scratch buffer and then RMA from
		 * that. The buffer is freed in the rdma-write
		 * completion handler.
		 */
		rpc->rma_buf = mm_alloc(client->heap, obj_sz);
		if (!rpc->rma_buf) {
			dsosd_error("rpc %p ep %p RMA heap empty\n", rpc, rpc->client->ep);
			dsosd_rpc_complete(rpc, ENOMEM);
			return;
		}
		rpc->ctxt = obj;
		memcpy(rpc->rma_buf, obj_data, obj_sz);
		zerr = zap_write(rpc->client->ep,
				 client->lmap, rpc->rma_buf,		/* src */
				 client->rmap, (void *)obj_remote_va,	/* dst */
				 obj_sz, rpc);
		if (zerr) {
			dsosd_error("rpc %p ep %p zap_write err %d %s\n",
				    rpc, rpc->client->ep, zerr, zap_err_str(zerr));
			dsosd_rpc_complete(rpc, zerr);
			return;
		}
		dsosd_rpc_debug("rpc %p rma obj %p rma_buf %p va %p obj_data %p sz %d\n", rpc,
				obj, rpc->rma_buf, obj_remote_va, obj_data, obj_sz);
#endif
	}
}

zap_err_t dsosd_rpc_complete(dsosd_rpc_t *rpc, int status)
{
	zap_err_t	zerr;

	/* Handle response-buffer serialization overflow from packing the response. */
	if (rpc->resp.p == NULL) {
		rpc->resp.len = sizeof(dsos_msg_t);
		status = E2BIG;
	}

	dsosd_rpc_debug("rpc %p ep %p msg %p id %ld len %d status %d\n", rpc, rpc->client->ep,
			rpc->resp.msg, rpc->resp.msg->hdr.id, rpc->resp.len, status);

	rpc->resp.msg->hdr.status = status;

#ifdef RPC_DEBUG
	{
	char *s;

	asprintf(&s, "Response to client %p:", rpc->client);
	dsos_buf_dump(stdout, &rpc->resp, s);
	free(s);
	}
#endif

	zerr = zap_send(rpc->client->ep, rpc->resp.msg, rpc->resp.len);
	if (zerr)
		dsosd_error("zap_send ep %p msg %p len %d zerr %d %s\n",
			    rpc->client->ep, rpc->resp.msg, rpc->resp.len, zerr,
			    zap_err_str(zerr));
	dsosd_rpc_put(rpc);
	return zerr;
}

void dsosd_rpc_get(dsosd_rpc_t *rpc)
{
	ods_atomic_inc(&rpc->refcount);
}

void dsosd_rpc_put(dsosd_rpc_t *rpc)
{
	dsosd_rpc_debug("%p\n", rpc);
	if (!ods_atomic_dec(&rpc->refcount)) {
		if (rpc->req.free_fn && rpc->req.msg)
			rpc->req.free_fn(rpc->req.msg);
		if (rpc->resp.free_fn && rpc->resp.msg)
			rpc->resp.free_fn(rpc->resp.msg);
		dsosd_client_put(rpc->client);
		free(rpc);
	}
}

int dsosd_rpc_pack_u32(dsosd_rpc_t *rpc, uint32_t val)
{
	return dsos_pack_u32(&rpc->resp, val);
}

int dsosd_rpc_pack_fits(dsosd_rpc_t *rpc, int len)
{
	return dsos_pack_fits(&rpc->resp, len);
}

int dsosd_rpc_pack_obj_needs(sos_obj_t obj)
{
	return dsos_pack_obj_needs(obj);
}

int dsosd_rpc_pack_obj(dsosd_rpc_t *rpc, sos_obj_t obj)
{
	return dsos_pack_obj(&rpc->resp, obj);
}

int dsosd_rpc_pack_obj_id(dsosd_rpc_t *rpc, sos_obj_ref_t obj_id)
{
	return dsos_pack_obj_id(&rpc->resp, obj_id);
}

int dsosd_rpc_pack_handle(dsosd_rpc_t *rpc, dsos_handle_t handle)
{
	return dsos_pack_u64(&rpc->resp, handle);
}

int dsosd_rpc_pack_schema(dsosd_rpc_t *rpc, sos_schema_t schema)
{
	return dsos_pack_schema(&rpc->resp, schema);
}

dsos_handle_t dsosd_rpc_unpack_handle(dsosd_rpc_t *rpc)
{
	return dsos_unpack_handle(&rpc->req);
}

uint32_t dsosd_rpc_unpack_u32(dsosd_rpc_t *rpc)
{
	return dsos_unpack_u32(&rpc->req);
}

char *dsosd_rpc_unpack_str(dsosd_rpc_t *rpc)
{
	return dsos_unpack_str(&rpc->req);
}

int dsosd_rpc_unpack_obj(dsosd_rpc_t *rpc, sos_obj_t obj)
{
	return dsos_unpack_obj(&rpc->req, obj);
}

uint64_t dsosd_rpc_unpack_obj_ptr(dsosd_rpc_t *rpc, uint64_t *plen)
{
	return dsos_unpack_obj_ptr(&rpc->req, plen);
}

sos_obj_ref_t dsosd_rpc_unpack_obj_id(dsosd_rpc_t *rpc)
{
	return dsos_unpack_obj_id(&rpc->req);
}

sos_schema_t dsosd_rpc_unpack_schema(dsosd_rpc_t *rpc)
{
	return dsos_unpack_schema(&rpc->req);
}

sos_key_t dsosd_rpc_unpack_key(dsosd_rpc_t *rpc)
{
	return dsos_unpack_key(&rpc->req);
}

sos_attr_t dsosd_rpc_unpack_attr(dsosd_rpc_t *rpc)
{
	sos_schema_t	schema  = dsosd_rpc_unpack_handle_to_ptr(rpc, DSOSD_HANDLE_SCHEMA);
	uint32_t	attr_id = dsos_unpack_u32(&rpc->req);

	if (!schema)
		return NULL;
	return sos_schema_attr_by_id(schema, attr_id);
}

sos_value_t dsosd_rpc_unpack_value(dsosd_rpc_t *rpc)
{
	sos_attr_t	attr = dsosd_rpc_unpack_attr(rpc);
	char		*str = dsos_unpack_str(&rpc->req);
	sos_value_t	value;

	value = sos_value_new();
	value = sos_value_init(value, NULL, attr);
	sos_value_from_str(value, str, NULL);
	return value;
}

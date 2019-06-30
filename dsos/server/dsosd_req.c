#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "dsosd_priv.h"

size_t dsosd_msg_len(int type)
{
	switch (type) {
	    case DSOSD_MSG_PING_REQ:
		return sizeof(dsosd_msg_ping_req_t);
	    case DSOSD_MSG_PING_RESP:
		return sizeof(dsosd_msg_ping_resp_t);
	    case DSOSD_MSG_CONTAINER_NEW_REQ:
		return sizeof(dsosd_msg_container_new_req_t);
	    case DSOSD_MSG_CONTAINER_NEW_RESP:
		return sizeof(dsosd_msg_container_new_resp_t);
	    case DSOSD_MSG_CONTAINER_OPEN_REQ:
		return sizeof(dsosd_msg_container_open_req_t);
	    case DSOSD_MSG_CONTAINER_OPEN_RESP:
		return sizeof(dsosd_msg_container_open_resp_t);
	    case DSOSD_MSG_CONTAINER_CLOSE_REQ:
		return sizeof(dsosd_msg_container_close_req_t);
	    case DSOSD_MSG_CONTAINER_CLOSE_RESP:
		return sizeof(dsosd_msg_container_close_resp_t);
	    case DSOSD_MSG_ITERATOR_CLOSE_REQ:
		return sizeof(dsosd_msg_iterator_close_req_t);
	    case DSOSD_MSG_ITERATOR_CLOSE_RESP:
		return sizeof(dsosd_msg_iterator_close_resp_t);
	    case DSOSD_MSG_ITERATOR_NEW_REQ:
		return sizeof(dsosd_msg_iterator_new_req_t);
	    case DSOSD_MSG_ITERATOR_NEW_RESP:
		return sizeof(dsosd_msg_iterator_new_resp_t);
	    case DSOSD_MSG_ITERATOR_STEP_REQ:
		return sizeof(dsosd_msg_iterator_step_req_t);
	    case DSOSD_MSG_ITERATOR_STEP_RESP:
		return sizeof(dsosd_msg_iterator_step_resp_t);
	    case DSOSD_MSG_OBJ_CREATE_REQ:
		return sizeof(dsosd_msg_obj_create_req_t);
	    case DSOSD_MSG_OBJ_CREATE_RESP:
		return sizeof(dsosd_msg_obj_create_resp_t);
	    case DSOSD_MSG_OBJ_GET_REQ:
		return sizeof(dsosd_msg_obj_get_req_t);
	    case DSOSD_MSG_OBJ_GET_RESP:
		return sizeof(dsosd_msg_obj_get_resp_t);
	    case DSOSD_MSG_PART_CREATE_REQ:
		return sizeof(dsosd_msg_part_create_req_t);
	    case DSOSD_MSG_PART_CREATE_RESP:
		return sizeof(dsosd_msg_part_create_resp_t);
	    case DSOSD_MSG_PART_FIND_REQ:
		return sizeof(dsosd_msg_part_find_req_t);
	    case DSOSD_MSG_PART_FIND_RESP:
		return sizeof(dsosd_msg_part_find_resp_t);
	    case DSOSD_MSG_PART_SET_STATE_REQ:
		return sizeof(dsosd_msg_part_set_state_req_t);
	    case DSOSD_MSG_PART_SET_STATE_RESP:
		return sizeof(dsosd_msg_part_set_state_resp_t);
	    case DSOSD_MSG_SCHEMA_FROM_TEMPLATE_REQ:
		return sizeof(dsosd_msg_schema_from_template_req_t);
	    case DSOSD_MSG_SCHEMA_FROM_TEMPLATE_RESP:
		return sizeof(dsosd_msg_schema_from_template_resp_t);
	    case DSOSD_MSG_SCHEMA_ADD_REQ:
		return sizeof(dsosd_msg_schema_add_req_t);
	    case DSOSD_MSG_SCHEMA_ADD_RESP:
		return sizeof(dsosd_msg_schema_add_resp_t);
	    case DSOSD_MSG_SCHEMA_BY_NAME_REQ:
		return sizeof(dsosd_msg_schema_by_name_req_t);
	    case DSOSD_MSG_SCHEMA_BY_NAME_RESP:
		return sizeof(dsosd_msg_schema_by_name_resp_t);
	    default:
		dsosd_fatal("fix me\n");
	}
}

dsosd_req_t *dsosd_req_new(dsosd_client_t *client, uint16_t type, uint64_t msg_id, size_t max_msg_len)
{
	dsosd_req_t	*req;

	req = malloc(sizeof(dsosd_req_t));
	if (!req)
		dsosd_fatal("out of memory");

	req->refcount = 1;  // start with a reference
	req->client   = client;
	req->resp     = malloc(max_msg_len);
	if (!req->resp)
		dsosd_fatal("out of memory\n");
	req->resp_max_len       = max_msg_len;
	req->resp->u.hdr.type   = type;
	req->resp->u.hdr.id     = msg_id;
	req->resp->u.hdr.status = 0;
	req->resp->u.hdr.flags  = 0;

	dsosd_client_get(client);

	dsosd_debug("%p client %p type %d\n", req, client, type);

	return req;
}

dsosd_req_t *dsosd_req_complete_with_obj(zap_ep_t ep, sos_obj_t sos_obj,
					 uint16_t resp_type, dsosd_msg_t *msg)
{
	zap_err_t	zerr;
	size_t		resp_len;
	dsosd_req_t	*req;
	char		*obj_data;
	size_t		obj_sz;
	uint64_t	client_buf_va;
	uint64_t	client_buf_sz;
	dsosd_client_t	*client = (dsosd_client_t *)zap_get_ucontext(ep);

	client_buf_va = msg->u.hdr2.obj_va;
	client_buf_sz = msg->u.hdr2.obj_sz;

	sos_obj_data_get(sos_obj, &obj_data, &obj_sz);

	resp_len = dsosd_msg_len(resp_type);

	if ((resp_len + obj_sz) < zap_max_msg(g.zap)) {
		/* Send object in-line within the response msg. */
		req = dsosd_req_new(client, resp_type, msg->u.hdr.id, resp_len + obj_sz);
		if (!req)
			return NULL;
		req->resp->u.hdr.flags |= DSOSD_MSG_IMM;
		req->resp->u.hdr2.obj_sz = obj_sz;
		req->resp->u.hdr2.obj_id = dsosd_objid(sos_obj);
		memcpy((char *)req->resp + resp_len, obj_data, obj_sz);
		sos_obj_put(sos_obj);
		dsosd_debug("inline obj_data %p obj_sz %d resp_len %d\n",
			    obj_data, obj_sz, resp_len + obj_sz);
		dsosd_req_complete(req, resp_len + obj_sz);
	} else {
		/* RMA-write the object to the client's buffer. */
		req = dsosd_req_new(client, resp_type, msg->u.hdr.id, resp_len);
		if (!req)
			return NULL;
		if (client_buf_sz < obj_sz) {
			dsosd_error("client buf too small; is %d need %d\n", client_buf_sz, obj_sz);
			req->resp->u.hdr.status = E2BIG;
			req->resp->u.hdr.flags  = 0;
			dsosd_req_complete(req, resp_len);
		}
		// This currently is true of the dsos client but may change in the future.
		assert (client_buf_sz == obj_sz);
#if 1
		/*
		 * We RMA from req->rma_buf for the moment. Once SOS
		 * is enhanced to register the ODS maps, can RMA-write
		 * to the client directly from the object. Until then,
		 * we copy into a scratch buffer and then RMA from
		 * that. The buffer is freed in the rdma-write
		 * completion handler.
		 */
		req->rma_buf = mm_alloc(client->heap, obj_sz);
		if (!req->rma_buf)
			return NULL;
		req->resp->u.hdr2.obj_sz = obj_sz;
		req->resp->u.hdr2.obj_id = dsosd_objid(sos_obj);
		req->resp_len = resp_len;
		req->ctxt = sos_obj;
		memcpy(req->rma_buf, obj_data, obj_sz);
		zerr = zap_write(ep,
				 client->lmap, req->rma_buf,            /* src */
				 client->rmap, (void *)client_buf_va,   /* dst */
				 obj_sz, req);
		if (zerr) {
			dsosd_error("ep %p zap_write err %d %s\n", ep, zerr, zap_err_str(zerr));
			req->resp->u.hdr.status = zerr;
			req->resp->u.hdr.flags  = 0;
			dsosd_req_complete(req, resp_len);
		}
		dsosd_debug("rma rma_buf %p obj_data %p obj_sz %d\n",
			    req->rma_buf, obj_data, obj_sz);
#endif
	}
	return req;
}

zap_err_t dsosd_req_complete_with_status(dsosd_client_t *client, uint16_t type, uint64_t msg_id,
					 size_t len, int status)
{
	dsosd_req_t *req = dsosd_req_new(client, type, msg_id, len);
	req->resp->u.hdr.status = status;
	return dsosd_req_complete(req, len);
}

zap_err_t dsosd_req_complete(dsosd_req_t *req, size_t len)
{
	zap_err_t	zerr;

	dsosd_debug("req %p ep %p len %d\n", req, req->client->ep, len);

	zerr = zap_send(req->client->ep, req->resp, len);
	if (zerr)
		dsosd_error("zap_send ep %p zerr %d %s\n", req->client->ep, zerr, zap_err_str(zerr));
	dsosd_req_put(req);
	return zerr;
}

void dsosd_req_get(dsosd_req_t *req)
{
	ods_atomic_inc(&req->refcount);
}

void dsosd_req_put(dsosd_req_t *req)
{
	dsosd_debug("%p\n", req);
	if (!ods_atomic_dec(&req->refcount)) {
		dsosd_client_put(req->client);
		free(req->resp);
		free(req);
	}
}

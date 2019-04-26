#include <stdlib.h>
#include <string.h>
#include "dsosd_priv.h"

static void	*rpc_serialize_schema(sos_schema_t schema, void *buf, size_t *psz);
static void	rpc_free_schema_template(sos_schema_template_t t);
static void	dump_schema_template(sos_schema_template_t t);

static dsosd_handle_t dsosd_ptr_to_handle(void *ptr)
{
	return (dsosd_handle_t)ptr;
}

static void *dsosd_handle_to_ptr(dsosd_handle_t handle)
{
	return (void *)handle;
}

void rpc_handle_ping(zap_ep_t ep, dsosd_msg_ping_req_t *msg, size_t len)
{
	dsosd_req_t		*req;
	zap_err_t		zerr;
	dsosd_client_t		*client = (dsosd_client_t *)zap_get_ucontext(ep);

	dsosd_debug("ep %p msg %p len %d\n", ep, msg, len);

	req = dsosd_req_new(client, DSOSD_MSG_PING_RESP, msg->hdr.id,
			    sizeof(dsosd_msg_ping_resp_t) + 16);
	req->resp->u.ping_resp.tot_num_connects    = g.stats.tot_num_connects;
	req->resp->u.ping_resp.tot_num_disconnects = g.stats.tot_num_disconnects;
	req->resp->u.ping_resp.tot_num_reqs        = g.stats.tot_num_reqs;
	req->resp->u.ping_resp.num_clients         = g.num_clients;
	strcpy(req->resp->u.ping_resp.data, "ping response");

	dsosd_req_complete(req, sizeof(dsosd_msg_ping_resp_t)+16);
}

void rpc_handle_obj_create(zap_ep_t ep, dsosd_msg_obj_create_req_t *msg, size_t len)
{
	int			ret;
	char			*obj_data;
	size_t			obj_max_sz;
	zap_err_t		zerr;
	dsosd_req_t		*req;
	sos_schema_t		schema;
	sos_obj_t		obj;
	dsosd_client_t		*client = (dsosd_client_t *)zap_get_ucontext(ep);

	dsosd_debug("ep %p msg %p len %d obj: va %p len %d handle %p\n",
		    ep, msg, len, msg->va, msg->len, msg->schema_handle);

	schema = dsosd_handle_to_ptr(msg->schema_handle);

	req = dsosd_req_new(client, DSOSD_MSG_OBJ_CREATE_RESP, msg->hdr.id,
			    sizeof(dsosd_msg_obj_create_resp_t));
	dsosd_objid_next(&req->resp->u.obj_create_resp.obj_id, schema);
	req->resp->u.obj_create_resp.len = msg->len;

	obj = sos_obj_new(schema);
	if (!obj) {
		req->resp->u.hdr.status = ENOMEM;
		req->resp->u.hdr.flags  = 0;
		dsosd_debug("error creating obj\n");
		dsosd_req_complete(req, sizeof(dsosd_msg_obj_create_resp_t));
		return;
	}
	sos_obj_data_get(obj, &obj_data, &obj_max_sz);
	dsosd_debug("new obj %p obj_data %p obj_max_sz %d id %08lx%08lx\n",
		    obj, obj_data, obj_max_sz,
		    req->resp->u.obj_create_resp.obj_id.hi,
		    req->resp->u.obj_create_resp.obj_id.lo);

	if (msg->hdr.flags & DSOSD_MSG_IMM) {
		/* The object data is in the recv buffer. Copy it to the object. */
		memcpy(obj_data, msg->data, msg->len);
		*(uint64_t *)obj_data = sos_schema_id(schema);
		ret = sos_obj_index(obj);
		if (ret)
			dsosd_error("ep %p sos_obj_index ret %d\n", ep, ret);
		sos_obj_put(obj);
		req->resp->u.hdr.status = ret;
		req->resp->u.hdr.flags  = DSOSD_MSG_IMM;
		dsosd_req_complete(req, sizeof(dsosd_msg_obj_create_resp_t));
	} else {
		/* RMA-read the object from client memory. */
		req->ctxt = obj;
		/*
		 * We RMA into client->testbuf for the moment. Once SOS is enhanced
		 * to take a heap allocator, we can allocate the object in a
		 * shared heap so the server can RMA-read it directly. Until
		 * then, we RMA into a scratch buffer and then memcpy into the
		 * object from that in the completion handler.
		 */
		zerr = zap_read(ep,
				client->rmap, (char *)msg->va,    /* src */
				client->lmap, client->testbuf,    /* dst */
				msg->len, req);
		if (zerr) {
			dsosd_error("zap_read ep %p zerr %d %s\n", ep, zerr, zap_err_str(zerr));
			req->resp->u.hdr.status = zerr;
			req->resp->u.hdr.flags  = 0;
			dsosd_req_complete(req, sizeof(dsosd_msg_obj_create_resp_t));
		}
	}
}

void rpc_handle_container_new(zap_ep_t ep, dsosd_msg_container_new_req_t *msg, size_t len)
{
	int			ret;
	dsosd_req_t		*req;
	dsosd_client_t		*client = (dsosd_client_t *)zap_get_ucontext(ep);

	ret = sos_container_new(msg->path, msg->mode);

	req = dsosd_req_new(client, DSOSD_MSG_CONTAINER_NEW_RESP, msg->hdr.id,
			    sizeof(dsosd_msg_container_new_resp_t));
	if (ret)
		req->resp->u.hdr.status = ret;

	dsosd_debug("ep %d msg %p len %d: '%s' perms 0%o, ret %d\n", ep, msg, len,
		    msg->path, msg->mode, ret);

	dsosd_req_complete(req, sizeof(dsosd_msg_container_new_resp_t));
}

void rpc_handle_container_open(zap_ep_t ep, dsosd_msg_container_open_req_t *msg, size_t len)
{
	dsosd_req_t		*req;
	sos_t			cont;
	dsosd_client_t		*client = (dsosd_client_t *)zap_get_ucontext(ep);

	cont = sos_container_open(msg->path, msg->perms);

	req = dsosd_req_new(client, DSOSD_MSG_CONTAINER_OPEN_RESP, msg->hdr.id,
			    sizeof(dsosd_msg_container_open_resp_t));

	if (cont)
		req->resp->u.container_open_resp.handle = dsosd_ptr_to_handle(cont);
	else
		req->resp->u.hdr.status = ENOENT;

	dsosd_debug("ep %d msg %p len %d: '%s' perms 0%o, cont %p\n", ep, msg, len,
		    msg->path, msg->perms, cont);

	dsosd_req_complete(req, sizeof(dsosd_msg_container_open_resp_t));
}

void rpc_handle_container_close(zap_ep_t ep, dsosd_msg_container_close_req_t *msg, size_t len)
{
	dsosd_req_t		*req;
	sos_t			cont;
	dsosd_client_t		*client = (dsosd_client_t *)zap_get_ucontext(ep);

	cont = (sos_t)dsosd_handle_to_ptr(msg->handle);
	sos_container_close(cont, SOS_COMMIT_SYNC);

	req = dsosd_req_new(client, DSOSD_MSG_CONTAINER_CLOSE_RESP, msg->hdr.id,
			    sizeof(dsosd_msg_container_close_resp_t));

	dsosd_debug("ep %d msg %p len %d: handle %p\n", ep, msg, len, msg->handle);

	dsosd_req_complete(req, sizeof(dsosd_msg_container_close_resp_t));
}

void rpc_handle_schema_by_name(zap_ep_t ep, dsosd_msg_schema_by_name_req_t *msg, size_t len)
{
	char			*p;
	size_t			sz;
	dsosd_req_t		*req;
	sos_t			cont;
	sos_schema_t		schema;
	dsosd_client_t		*client = (dsosd_client_t *)zap_get_ucontext(ep);

	cont = (sos_t)dsosd_handle_to_ptr(msg->cont_handle);

	req = dsosd_req_new(client, DSOSD_MSG_SCHEMA_BY_NAME_RESP, msg->hdr.id,
			    sizeof(dsosd_msg_schema_by_name_resp_t));

	schema = sos_schema_by_name(cont, msg->name);
	if (schema) {
		req->resp->u.schema_by_name_resp.handle = dsosd_ptr_to_handle(schema);
		sz = sizeof(req->resp->u.schema_by_name_resp.templ);
		p = rpc_serialize_schema(schema,
					 req->resp->u.schema_by_name_resp.templ,
					 &sz);
		if (!p)
			req->resp->u.hdr.status = ENAMETOOLONG;
	} else {
		req->resp->u.hdr.status = ENOENT;
	}

	dsosd_debug("ep %d msg %p len %d: cont_handle %p schema %p\n", ep, msg, len,
		    msg->cont_handle, schema);

	dsosd_req_complete(req, sizeof(dsosd_msg_schema_by_name_resp_t));
}

void rpc_handle_schema_add(zap_ep_t ep, dsosd_msg_schema_add_req_t *msg, size_t len)
{
	int			ret;
	dsosd_req_t		*req;
	sos_t			cont;
	sos_schema_t		schema;
	dsosd_client_t		*client = (dsosd_client_t *)zap_get_ucontext(ep);

	cont   = (sos_t)dsosd_handle_to_ptr(msg->cont_handle);
	schema = (sos_schema_t)dsosd_handle_to_ptr(msg->schema_handle);

	req = dsosd_req_new(client, DSOSD_MSG_SCHEMA_ADD_RESP, msg->hdr.id,
			    sizeof(dsosd_msg_schema_add_resp_t));

	ret = sos_schema_add(cont, schema);
	if (ret)
		req->resp->u.hdr.status = ret;

	dsosd_debug("ep %d msg %p len %d: cont_handle %p schema_handle %p\n", ep, msg, len,
		    msg->cont_handle, msg->schema_handle);

	dsosd_req_complete(req, sizeof(dsosd_msg_schema_add_resp_t));
}

void rpc_handle_part_create(zap_ep_t ep, dsosd_msg_part_create_req_t *msg, size_t len)
{
	int			ret;
	dsosd_req_t		*req;
	sos_t			cont;
	dsosd_client_t		*client = (dsosd_client_t *)zap_get_ucontext(ep);

	dsosd_debug("ep %d msg %p len %d: cont_handle %p name %s path %s ret %d\n",
		    ep, msg, len, msg->cont_handle, msg->name, msg->path, ret);

	cont = (sos_t)dsosd_handle_to_ptr(msg->cont_handle);

	req = dsosd_req_new(client, DSOSD_MSG_PART_CREATE_RESP, msg->hdr.id,
			    sizeof(dsosd_msg_part_create_resp_t));

	if (!msg->path[0])
		ret = sos_part_create(cont, msg->name, NULL);
	else
		ret = sos_part_create(cont, msg->name, msg->path);
	if (ret)
		req->resp->u.hdr.status = ret;

	dsosd_debug("ep %d msg %p len %d: cont_handle %p name %s path %s ret %d\n",
		    ep, msg, len, msg->cont_handle, msg->name, msg->path, ret);

	dsosd_req_complete(req, sizeof(dsosd_msg_part_create_resp_t));
}

void rpc_handle_part_find(zap_ep_t ep, dsosd_msg_part_find_req_t *msg, size_t len)
{
	int			ret;
	dsosd_req_t		*req;
	sos_t			cont;
	sos_part_t		part;
	dsosd_client_t		*client = (dsosd_client_t *)zap_get_ucontext(ep);

	cont = (sos_t)dsosd_handle_to_ptr(msg->cont_handle);

	req = dsosd_req_new(client, DSOSD_MSG_PART_FIND_RESP, msg->hdr.id,
			    sizeof(dsosd_msg_part_find_resp_t));

	part = sos_part_find(cont, msg->name);
	if (part)
		req->resp->u.part_find_resp.handle = dsosd_ptr_to_handle(part);
	else
		req->resp->u.hdr.status = ENOENT;

	dsosd_debug("ep %d msg %p len %d: cont_handle %p name %s\n",
		    ep, msg, len, msg->cont_handle, msg->name);

	dsosd_req_complete(req, sizeof(dsosd_msg_part_find_resp_t));
}

void rpc_handle_part_set_state(zap_ep_t ep, dsosd_msg_part_set_state_req_t *msg, size_t len)
{
	int			ret;
	dsosd_req_t		*req;
	sos_part_t		part;
	dsosd_client_t		*client = (dsosd_client_t *)zap_get_ucontext(ep);

	part = (sos_part_t)dsosd_handle_to_ptr(msg->handle);

	req = dsosd_req_new(client, DSOSD_MSG_PART_SET_STATE_RESP, msg->hdr.id,
			    sizeof(dsosd_msg_part_set_state_resp_t));

	ret = sos_part_state_set(part, msg->new_state);
	if (ret)
		req->resp->u.hdr.status = ret;

	dsosd_debug("ep %d msg %p len %d: handle %p new_state %d\n",
		    ep, msg, len, msg->handle, msg->new_state);

	dsosd_req_complete(req, sizeof(dsosd_msg_part_set_state_resp_t));
}

void rpc_handle_schema_from_template(zap_ep_t ep, dsosd_msg_schema_from_template_req_t *msg, size_t len)
{
	int			ret;
	dsosd_req_t		*req;
	sos_t			cont;
	sos_schema_t		schema;
	sos_schema_template_t	template;
	dsosd_client_t		*client = (dsosd_client_t *)zap_get_ucontext(ep);

	req = dsosd_req_new(client, DSOSD_MSG_SCHEMA_FROM_TEMPLATE_RESP, msg->hdr.id,
			    sizeof(dsosd_msg_schema_from_template_resp_t));

	template = rpc_deserialize_schema_template(msg->templ, len - sizeof(dsosd_msg_hdr_t));
	if (!template) {
		req->resp->u.hdr.status = EINVAL;
		goto out;
		return;
	}

	schema = sos_schema_from_template(template);
	if (schema)
		req->resp->u.schema_from_template_resp.handle = dsosd_ptr_to_handle(schema);
	else
		req->resp->u.hdr.status = EINVAL;
 out:
	dsosd_debug("ep %d msg %p len %d: template %p\n", ep, msg, len, template);
	dump_schema_template(template);

	dsosd_req_complete(req, sizeof(dsosd_msg_schema_from_template_resp_t));

	rpc_free_schema_template(template);
}

static char *serialize_uint32(const int v, char **pp, size_t *psz)
{
	char	*ret = *pp;
	size_t	len = sizeof(uint32_t);

	if (len <= *psz) {
		*(uint32_t *)*pp = v;
		*pp  += len;
		*psz -= len;
		return ret;
	} else {
		*psz = -1;
		return NULL;
	}
}

static char *serialize_str(const char *v, char **pp, size_t *psz)
{
	char	*ret = *pp;
	size_t	len;

	len = 1;  // include NULL terminating byte
	if (v)
		len += strlen(v);
	if (len <= *psz) {
		if (v)
			strncpy(*pp, v, len);  // strncpy will write the terminating NULL
		else
			**pp = 0;
		*pp  += len;
		*psz -= len;
		return ret;
	} else {
		*psz = -1;
		return NULL;
	}
}

static uint32_t deserialize_uint32(char **pbuf, size_t *psz)
{
	uint32_t	ret = *(uint32_t *)*pbuf;
	size_t		len = sizeof(uint32_t);

	*pbuf += len;
	*psz  -= len;
	return ret;
}

static char *deserialize_str(char **pbuf, size_t *psz)
{
	char		*ret = *pbuf;
	size_t		len = strlen(ret) + 1;

	if (len == 1)
		ret = NULL;
	*pbuf += len;
	*psz  -= len;
	return ret;
}

static void *rpc_serialize_schema(sos_schema_t schema, void *buf, size_t *psz)
{
	int		i, j;
	uint32_t	*p_attrs_len, *p_joinlist_len;
	char		*p = buf;
	sos_attr_t	attr;

	serialize_str(schema->data->name, &p, psz);
	p_attrs_len = (uint32_t *)serialize_uint32(0, &p, psz);
	i = 0;
	TAILQ_FOREACH(attr, &schema->attr_list, entry) {
		serialize_str   (attr->data->name, &p, psz);
		serialize_uint32(attr->data->type, &p, psz);
		serialize_uint32(attr->data->size, &p, psz);
		p_joinlist_len = (uint32_t *)serialize_uint32(0, &p, psz);
		if (attr->ext_ptr) {
			for (j = 0; j < attr->ext_ptr->count; ++j) {
				sos_attr_t join_attr = sos_schema_attr_by_id(schema,
								attr->ext_ptr->data.uint32_[j]);
				serialize_str(sos_attr_name(join_attr), &p, psz);
			}
			if (*psz >= 0) *p_joinlist_len = j;
		}
		serialize_uint32(attr->idx_type ? 1 : 0,  &p, psz);
		serialize_str   (attr->idx_type, &p, psz);
		serialize_str   (attr->key_type, &p, psz);
		serialize_str   (attr->idx_args, &p, psz);
		++i;
	}
	if (*psz >= 0) {
		*p_attrs_len = i;
		*psz = p - (char *)buf;
		return buf;
	} else {
		return NULL;
	}
}

sos_schema_template_t rpc_deserialize_schema_template(char *buf, size_t len)
{
	int			i, j;
	char			*name;
	uint32_t		num_attrs, num_join_attrs;
	sos_schema_template_t	t;

	name      = deserialize_str(&buf, &len);
	num_attrs = deserialize_uint32(&buf, &len);

	t = (sos_schema_template_t)malloc(sizeof(struct sos_schema_template) +
					  sizeof(struct sos_schema_template_attr) * (num_attrs+1));
	if (!t)
		return NULL;

	t->name = name;
	for (i = 0; i < num_attrs; ++i) {
		t->attrs[i].name = deserialize_str   (&buf, &len);
		t->attrs[i].type = deserialize_uint32(&buf, &len);
		t->attrs[i].size = deserialize_uint32(&buf, &len);
		num_join_attrs   = deserialize_uint32(&buf, &len);
		t->attrs[i].join_list = NULL;
		if (num_join_attrs) {
			t->attrs[i].join_list = malloc(sizeof(char *) * num_join_attrs);
			for (j = 0; j < num_join_attrs; ++j)
				t->attrs[i].join_list[j] = deserialize_str(&buf, &len);
		}
		t->attrs[i].indexed  = deserialize_uint32(&buf, &len);
		t->attrs[i].idx_type = deserialize_str   (&buf, &len);
		t->attrs[i].key_type = deserialize_str   (&buf, &len);
		t->attrs[i].idx_args = deserialize_str   (&buf, &len);
	}
	t->attrs[i].name = NULL;

	return t;
}

static void rpc_free_schema_template(sos_schema_template_t t)
{
	int	i;

	for (i = 0; t->attrs[i].name; ++i) {
		if (t->attrs[i].join_list)
			free(t->attrs[i].join_list);
	}
	free(t);
}

static void dump_schema_template(sos_schema_template_t t)
{
	int				i, j;
	sos_schema_template_attr_t	attr;

	dsosd_debug("template %p name %s\n", t, t->name);
	for (i = 0; t->attrs[i].name; ++i) {
		dsosd_debug("attr: %s type %d sz %d ix %d ixtyp %s keytyp %s idxargs %s\n",
			    t->attrs[i].name,
			    t->attrs[i].type,
			    t->attrs[i].size,
			    t->attrs[i].indexed,
			    t->attrs[i].idx_type,
			    t->attrs[i].key_type,
			    t->attrs[i].idx_args);
		if (t->attrs[i].join_list) {
			for (j = 0; j < t->attrs[i].size; ++j)
				dsosd_debug("join attr %s\n", t->attrs[i].join_list[j]);
		}
	}
}

// This will call into SOS soon to get a container-unique id.
void dsosd_objid_next(dsosd_objid_t *id, sos_schema_t schema)
{
	static uint64_t next_obj_id = 123123;  // XXX temporary for testing

	id->hi = 0;
	id->lo = next_obj_id++;
	id->bytes[15] = g.opts.server_num;
}

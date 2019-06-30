#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "dsosd_priv.h"

static void	*rpc_serialize_schema(sos_schema_t schema, void *buf, size_t *psz);
static void	rpc_free_schema_template(sos_schema_template_t t);
static void	dump_schema_template(sos_schema_template_t t);

dsosd_objid_t dsosd_objid(sos_obj_t sos_obj)
{
	dsosd_objid_t	obj_id;

	/*
	 * The DSOS object id is formed from the server # and the
	 * local ODS reference.  The two unique identify an object
	 * within a distributed container.  In DSOS we don't need
	 * the partition identifier, because the ROOT partition
	 * is always implied.
	 */
	obj_id.serv = g.opts.server_num;
	obj_id.obj  = sos_obj_ref(sos_obj).ref.obj;

	return obj_id;
}

static dsosd_handle_t dsosd_ptr_to_handle(dsosd_client_t *client, void *ptr)
{
	struct ptr_rbn	*rbn;
	dsosd_handle_t	handle = client->next_handle++;

	rbn = calloc(1, sizeof(struct ptr_rbn));
	if (!rbn)
		dsosd_fatal("out of memory\n");
	rbn_init((struct rbn *)rbn, (void *)handle);
	rbn->ptr = ptr;
	rbt_ins(&client->handle_rbt, (void *)rbn);
	dsosd_debug("client %p ptr %p assigned handle 0x%lx\n", client, ptr, handle);

	return handle;
}

static void *dsosd_handle_to_ptr(dsosd_client_t *client, dsosd_handle_t handle)
{
	struct ptr_rbn	*rbn;

	rbn = (struct ptr_rbn *)rbt_find(&client->handle_rbt, (void *)handle);
	if (!rbn) {
		dsosd_error("client %p handle 0x%lx not found\n", client, handle);
		return NULL;
	}
	dsosd_debug("client %p handle 0x%lx is ptr %p\n", client, handle, rbn->ptr);
	return rbn->ptr;
}

static void dsosd_handle_free(dsosd_client_t *client, dsosd_handle_t handle)
{
	struct ptr_rbn	*rbn;

	rbn = (struct ptr_rbn *)rbt_find(&client->handle_rbt, (void *)handle);
	if (rbn) {
		rbt_del(&client->handle_rbt, (struct rbn *)rbn);
		free(rbn);
	} else
		dsosd_error("client %p handle 0x%lx not found\n", client, handle);
}

void rpc_handle_ping(zap_ep_t ep, dsosd_msg_ping_req_t *msg, size_t len)
{
	dsosd_req_t		*req;
	zap_err_t		zerr;
	dsosd_client_t		*client = (dsosd_client_t *)zap_get_ucontext(ep);

	dsosd_debug("ep %p msg %p len %d\n", ep, msg, len);

	req = dsosd_req_new(client, DSOSD_MSG_PING_RESP, msg->hdr.id,
			    sizeof(dsosd_msg_ping_resp_t));
	req->resp->u.ping_resp.tot_num_connects    = g.stats.tot_num_connects;
	req->resp->u.ping_resp.tot_num_disconnects = g.stats.tot_num_disconnects;
	req->resp->u.ping_resp.tot_num_reqs        = g.stats.tot_num_reqs;
	req->resp->u.ping_resp.num_clients         = g.num_clients;

	dsosd_req_complete(req, sizeof(dsosd_msg_ping_resp_t));
}

void rpc_handle_obj_create(zap_ep_t ep, dsosd_msg_obj_create_req_t *msg, size_t len)
{
	int				ret;
	char				*obj_data;
	size_t				obj_max_sz;
	zap_err_t			zerr;
	dsosd_req_t			*req;
	dsosd_msg_obj_create_resp_t	*resp;
	sos_schema_t			schema;
	sos_obj_t			obj;
	dsosd_client_t			*client = (dsosd_client_t *)zap_get_ucontext(ep);

	dsosd_debug("ep %p msg %p len %d obj: va %p len %d handle %p\n",
		    ep, msg, len, msg->hdr2.obj_va, msg->hdr2.obj_sz, msg->schema_handle);

	req = dsosd_req_new(client, DSOSD_MSG_OBJ_CREATE_RESP, msg->hdr.id,
			    sizeof(dsosd_msg_obj_create_resp_t));

	resp = (dsosd_msg_obj_create_resp_t *)req->resp;
	resp->hdr2.obj_sz = msg->hdr2.obj_sz;

	schema = dsosd_handle_to_ptr(client, msg->schema_handle);
	if (!schema) {
		resp->hdr.status = EBADF;
		resp->hdr.flags  = 0;
		dsosd_req_complete(req, sizeof(dsosd_msg_obj_create_resp_t));
		return;
	}

	obj = sos_obj_new(schema);
	if (!obj) {
		resp->hdr.status = ENOMEM;
		resp->hdr.flags  = 0;
		dsosd_error("error %d creating obj\n", errno);
		dsosd_req_complete(req, sizeof(dsosd_msg_obj_create_resp_t));
		return;
	}
	sos_obj_data_get(obj, &obj_data, &obj_max_sz);
	assert(resp->hdr2.obj_sz == obj_max_sz);

	resp->hdr2.obj_id = dsosd_objid(obj);

	dsosd_debug("new obj %p obj_data %p obj_sz %d id %08lx%08lx\n",
		    obj, obj_data, obj_max_sz,
		    resp->hdr2.obj_id.serv,
		    resp->hdr2.obj_id.obj);

	if (msg->hdr.flags & DSOSD_MSG_IMM) {
		/* The object data is in the recv buffer. Copy it to the object. */
		memcpy(obj_data, msg->data, msg->hdr2.obj_sz);
		*(uint64_t *)obj_data = sos_schema_id(schema);
		ret = sos_obj_index(obj);
		if (ret)
			dsosd_error("ep %p sos_obj_index ret %d\n", ep, ret);
		sos_obj_put(obj);
		resp->hdr.status = ret;
		resp->hdr.flags  = DSOSD_MSG_IMM;
		dsosd_req_complete(req, sizeof(dsosd_msg_obj_create_resp_t));
	} else {
		/* RMA-read the object from client memory. */
		req->ctxt = obj;
#if 1
		/*
		 * We RMA into req->rma_buf for the moment. Once SOS
		 * is enhanced to map object memory, the server can
		 * RMA-read it directly. Until then, we RMA into a
		 * scratch buffer and then memcpy into the object from
		 * that in the completion handler.
		 */
		req->rma_buf = mm_alloc(client->heap, msg->hdr2.obj_sz);
		if (!req->rma_buf)
			dsosd_fatal("could not alloc from shared heap\n");
		zerr = zap_read(ep,
				client->rmap, (char *)msg->hdr2.obj_va,   /* src */
				client->lmap, req->rma_buf,               /* dst */
				msg->hdr2.obj_sz, req);
#endif
		if (zerr) {
			dsosd_error("zap_read ep %p zerr %d %s\n", ep, zerr, zap_err_str(zerr));
			resp->hdr.status = zerr;
			resp->hdr.flags  = 0;
			dsosd_req_complete(req, sizeof(dsosd_msg_obj_create_resp_t));
			sos_obj_put(obj);
		}
	}
}

void rpc_handle_obj_delete(zap_ep_t ep, dsosd_msg_obj_delete_req_t *msg, size_t len)
{
	int				ret;
	sos_t				cont;
	sos_part_t			part;
	sos_obj_t			obj;
	sos_obj_ref_t			obj_ref;
	dsosd_client_t			*client = (dsosd_client_t *)zap_get_ucontext(ep);

	cont = (sos_t)dsosd_handle_to_ptr(client, msg->cont_handle);
	if (!cont) {
		ret = EBADF;
		goto out;
	}

	/*
	 * Re-create the local object reference from the DSOS reference.
	 */
	obj_ref = msg->hdr2.obj_id.as_ref;
	part = sos_part_find(cont, "ROOT");
	if (!part) {
		ret = EBADFD;
		goto out;
	}
	obj_ref.ref.ods = sos_part_id(part);

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
	dsosd_debug("status %d ep %d msg %p len %d: cont %p/%p part %p id %d obj %p %08lx%08lx\n",
		    ret, ep, msg, len, msg->cont_handle, cont, part, sos_part_id(part),
		    obj, msg->hdr2.obj_id.serv, msg->hdr2.obj_id.obj);

	dsosd_req_complete_with_status(client, DSOSD_MSG_OBJ_DELETE_RESP, msg->hdr.id,
				       sizeof(dsosd_msg_obj_delete_resp_t), ret);
}

static char *rewrite_path(char *path)
{
	char	*server_num;

	asprintf(&server_num, "%d", g.opts.server_num);
	path = str_replace(path, "%%", server_num);
	free(server_num);
	return path;
}

void rpc_handle_container_new(zap_ep_t ep, dsosd_msg_container_new_req_t *msg, size_t len)
{
	int			ret;
	dsosd_client_t		*client = (dsosd_client_t *)zap_get_ucontext(ep);
	char			*path;

	path = rewrite_path(msg->path);

	ret = sos_container_new(path, msg->mode);

	dsosd_debug("ep %d msg %p len %d: '%s' perms 0%o, ret %d\n", ep, msg, len,
		    path, msg->mode, ret);

	dsosd_req_complete_with_status(client, DSOSD_MSG_CONTAINER_NEW_RESP, msg->hdr.id,
				       sizeof(dsosd_msg_container_new_resp_t), ret);
	free(path);
}

void rpc_handle_container_open(zap_ep_t ep, dsosd_msg_container_open_req_t *msg, size_t len)
{
	dsosd_req_t		*req;
	sos_t			cont;
	dsosd_client_t		*client = (dsosd_client_t *)zap_get_ucontext(ep);
	char			*path;

	path = rewrite_path(msg->path);

	cont = sos_container_open(path, msg->perms);

	req = dsosd_req_new(client, DSOSD_MSG_CONTAINER_OPEN_RESP, msg->hdr.id,
			    sizeof(dsosd_msg_container_open_resp_t));
	if (cont)
		req->resp->u.container_open_resp.handle = dsosd_ptr_to_handle(client, cont);
	else
		req->resp->u.hdr.status = ENOENT;

	dsosd_debug("ep %d msg %p len %d: '%s' perms 0%o, cont %p/%p\n", ep, msg, len,
		    path, msg->perms, cont, req->resp->u.container_open_resp.handle);

	dsosd_req_complete(req, sizeof(dsosd_msg_container_open_resp_t));
	free(path);
}

/*
 * This command is dangerous in the sense that it does an rm -rf of a
 * path passed in as an RPC argument. This is used for testing and
 * probably should remain undocumented.
 */
void rpc_handle_container_delete(zap_ep_t ep, dsosd_msg_container_delete_req_t *msg, size_t len)
{
	int			ret;
	char			*cmd;
	dsosd_client_t		*client = (dsosd_client_t *)zap_get_ucontext(ep);
	char			*path;

	path = rewrite_path(msg->path);

	if (asprintf(&cmd, "/usr/bin/rm -rf '%s'", path) < 0) {
		ret = ENOMEM;
	} else {
		ret = system(cmd);
		free(cmd);
	}

	dsosd_debug("ep %d msg %p len %d: '%s' ret %d\n", ep, msg, len, path, ret);

	dsosd_req_complete_with_status(client, DSOSD_MSG_CONTAINER_DELETE_RESP, msg->hdr.id,
				       sizeof(dsosd_msg_container_delete_resp_t), ret);
	free(path);
}

void rpc_handle_container_close(zap_ep_t ep, dsosd_msg_container_close_req_t *msg, size_t len)
{
	sos_t			cont;
	struct ptr_rbn		*rbn;
	dsosd_client_t		*client = (dsosd_client_t *)zap_get_ucontext(ep);

	cont = (sos_t)dsosd_handle_to_ptr(client, msg->handle);
	if (!cont) {
		dsosd_req_complete_with_status(client, DSOSD_MSG_CONTAINER_CLOSE_RESP, msg->hdr.id,
					       sizeof(dsosd_msg_container_close_resp_t), EBADF);
		return;
	}

	dsosd_debug("ep %d msg %p len %d: handle %p cont %p\n", ep, msg, len, msg->handle, cont);

	/* Close all indices the client has open in the container being closed. */
	while ((rbn = (struct ptr_rbn *)rbt_min(&client->idx_rbt))) {
		sos_index_t idx = (sos_index_t)rbn->ptr;
		if (idx->sos == cont) {
			dsosd_debug("closing idx %p\n", idx);
			rbt_del(&client->idx_rbt, (struct rbn *)rbn);
			sos_index_close((sos_index_t)rbn->ptr, SOS_COMMIT_ASYNC);
			free(rbn->rbn.key);
		}
	}

	sos_container_close(cont, SOS_COMMIT_SYNC);
	dsosd_handle_free(client, msg->handle);

	dsosd_req_complete_with_status(client, DSOSD_MSG_CONTAINER_CLOSE_RESP, msg->hdr.id,
				       sizeof(dsosd_msg_container_close_resp_t), 0);
}

void rpc_handle_schema_by_name(zap_ep_t ep, dsosd_msg_schema_by_name_req_t *msg, size_t len)
{
	char			*p;
	size_t			sz;
	dsosd_req_t		*req;
	sos_t			cont;
	sos_schema_t		schema;
	dsosd_client_t		*client = (dsosd_client_t *)zap_get_ucontext(ep);

	req = dsosd_req_new(client, DSOSD_MSG_SCHEMA_BY_NAME_RESP, msg->hdr.id,
			    sizeof(dsosd_msg_schema_by_name_resp_t));

	cont = (sos_t)dsosd_handle_to_ptr(client, msg->cont_handle);
	if (!cont) {
		req->resp->u.hdr.status = EBADF;
		req->resp->u.hdr.flags  = 0;
		dsosd_req_complete(req, sizeof(dsosd_msg_schema_by_name_resp_t));
		return;
	}
	schema = sos_schema_by_name(cont, msg->name);
	if (schema) {
		req->resp->u.schema_by_name_resp.handle = dsosd_ptr_to_handle(client, schema);
		sz = sizeof(req->resp->u.schema_by_name_resp.templ);
		p = rpc_serialize_schema(schema,
					 req->resp->u.schema_by_name_resp.templ,
					 &sz);
		if (!p)
			req->resp->u.hdr.status = ENAMETOOLONG;
	} else {
		req->resp->u.hdr.status = ENOENT;
	}

	dsosd_debug("ep %d msg %p len %d: cont %p/%p schema %p\n", ep, msg, len,
		    msg->cont_handle, cont, schema);

	dsosd_req_complete(req, sizeof(dsosd_msg_schema_by_name_resp_t));
}

void rpc_handle_schema_add(zap_ep_t ep, dsosd_msg_schema_add_req_t *msg, size_t len)
{
	int			ret;
	sos_t			cont;
	sos_schema_t		schema;
	dsosd_client_t		*client = (dsosd_client_t *)zap_get_ucontext(ep);

	cont   = (sos_t)dsosd_handle_to_ptr(client, msg->cont_handle);
	schema = (sos_schema_t)dsosd_handle_to_ptr(client, msg->schema_handle);
	if (!cont || !schema) {
		dsosd_req_complete_with_status(client, DSOSD_MSG_SCHEMA_ADD_RESP, msg->hdr.id,
					       sizeof(dsosd_msg_schema_add_resp_t), EBADF);
		return;
	}

	ret = sos_schema_add(cont, schema);

	dsosd_debug("ep %d msg %p len %d: cont %p/%p schema %p/%p\n", ep, msg, len,
		    msg->cont_handle, cont, msg->schema_handle, schema);

	dsosd_req_complete_with_status(client, DSOSD_MSG_SCHEMA_ADD_RESP, msg->hdr.id,
				       sizeof(dsosd_msg_schema_add_resp_t), ret);
}

void rpc_handle_part_create(zap_ep_t ep, dsosd_msg_part_create_req_t *msg, size_t len)
{
	int			ret;
	sos_t			cont;
	dsosd_client_t		*client = (dsosd_client_t *)zap_get_ucontext(ep);

	cont = (sos_t)dsosd_handle_to_ptr(client, msg->cont_handle);
	if (!cont) {
		dsosd_req_complete_with_status(client, DSOSD_MSG_PART_CREATE_RESP, msg->hdr.id,
					       sizeof(dsosd_msg_part_create_resp_t), EBADF);
		return;
	}

	if (!msg->path[0])
		ret = sos_part_create(cont, msg->name, NULL);
	else
		ret = sos_part_create(cont, msg->name, msg->path);

	dsosd_debug("ep %d msg %p len %d: cont_handle %p name %s path %s ret %d\n",
		    ep, msg, len, msg->cont_handle, msg->name, msg->path, ret);

	dsosd_req_complete_with_status(client, DSOSD_MSG_PART_CREATE_RESP, msg->hdr.id,
				       sizeof(dsosd_msg_part_create_resp_t), ret);
}

void rpc_handle_part_find(zap_ep_t ep, dsosd_msg_part_find_req_t *msg, size_t len)
{
	int			ret;
	dsosd_req_t		*req;
	sos_t			cont;
	sos_part_t		part;
	dsosd_client_t		*client = (dsosd_client_t *)zap_get_ucontext(ep);

	req = dsosd_req_new(client, DSOSD_MSG_PART_FIND_RESP, msg->hdr.id,
			    sizeof(dsosd_msg_part_find_resp_t));

	cont = (sos_t)dsosd_handle_to_ptr(client, msg->cont_handle);
	if (!cont) {
		req->resp->u.hdr.status = EBADF;
		req->resp->u.hdr.flags  = 0;
		dsosd_req_complete(req, sizeof(dsosd_msg_part_find_resp_t));
		return;
	}

	part = sos_part_find(cont, msg->name);
	if (part)
		req->resp->u.part_find_resp.handle = dsosd_ptr_to_handle(client, part);
	else
		req->resp->u.hdr.status = ENOENT;

	dsosd_debug("ep %d msg %p len %d: cont %p/%p name %s\n",
		    ep, msg, len, msg->cont_handle, cont, msg->name);

	dsosd_req_complete(req, sizeof(dsosd_msg_part_find_resp_t));
}

void rpc_handle_part_set_state(zap_ep_t ep, dsosd_msg_part_set_state_req_t *msg, size_t len)
{
	int			ret;
	sos_part_t		part;
	dsosd_client_t		*client = (dsosd_client_t *)zap_get_ucontext(ep);

	part = (sos_part_t)dsosd_handle_to_ptr(client, msg->handle);

	ret = sos_part_state_set(part, msg->new_state);

	/*
	 * The part object is unavailable after this. This is for ease of use
	 * in the common case where we create a partition, set its state,
	 * then begin using the container.
	 */
	sos_part_put(part);
	dsosd_handle_free(client, msg->handle);

	dsosd_debug("ep %d msg %p len %d: part %p/%p new_state %d\n",
		    ep, msg, len, msg->handle, part, msg->new_state);

	dsosd_req_complete_with_status(client, DSOSD_MSG_PART_SET_STATE_RESP, msg->hdr.id,
				       sizeof(dsosd_msg_part_set_state_resp_t), ret);
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
		req->resp->u.schema_from_template_resp.handle = dsosd_ptr_to_handle(client, schema);
	else
		req->resp->u.hdr.status = EINVAL;
 out:
	dsosd_debug("ep %d msg %p len %d: template %p\n", ep, msg, len, template);

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
		if (attr->data->el_sz)
			serialize_uint32(attr->data->count, &p, psz);
		else
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
		serialize_uint32(attr->data->indexed, &p, psz);
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

int deserialize_buf(char **val_data, char **pbuf, size_t *psz)
{
	uint32_t	count;

	count = deserialize_uint32(pbuf, psz);
	*val_data = *pbuf;
	*pbuf += count;
	*psz  -= count;
	return count;
}

void rpc_handle_obj_get(zap_ep_t ep, dsosd_msg_obj_get_req_t *msg, size_t len)
{
	sos_t		cont;
	sos_obj_t	sos_obj;
	sos_part_t	primary;
	dsosd_req_t	*req;
	dsosd_client_t	*client = (dsosd_client_t *)zap_get_ucontext(ep);

	cont = dsosd_handle_to_ptr(client, msg->cont_handle);
	if (!cont) {
		dsosd_req_complete_with_status(client, DSOSD_MSG_OBJ_GET_RESP, msg->hdr.id,
					       sizeof(dsosd_msg_obj_get_resp_t), EBADF);
		return;
	}

	/* Use the ODS from the primary partition in the given container. */
	primary = __sos_primary_obj_part(cont);
	if (!primary)
		return;
	msg->obj_id.as_ref.ref.ods = sos_part_id(primary);

	sos_obj = sos_ref_as_obj(cont, msg->obj_id.as_ref);

	dsosd_debug("ep %p obj_id %08lx%08lx sos_obj %p\n", ep,
		    msg->obj_id.as_ref.ref.ods, msg->obj_id.as_ref.ref.obj,
		    sos_obj);

	if (sos_obj)
		dsosd_req_complete_with_obj(ep, sos_obj, DSOSD_MSG_OBJ_GET_RESP, msg);
	else
		dsosd_req_complete_with_status(client, DSOSD_MSG_OBJ_GET_RESP, msg->hdr.id,
					       sizeof(dsosd_msg_obj_get_resp_t), ENOENT);
}

void rpc_handle_iterator_close(zap_ep_t ep, dsosd_msg_iterator_close_req_t *msg, size_t len)
{
	sos_iter_t	iter;
	dsosd_client_t	*client = (dsosd_client_t *)zap_get_ucontext(ep);

	iter = (sos_iter_t)dsosd_handle_to_ptr(client, msg->iter_handle);
	if (!iter) {
		dsosd_req_complete_with_status(client, DSOSD_MSG_ITERATOR_CLOSE_RESP, msg->hdr.id,
					       sizeof(dsosd_msg_iterator_close_resp_t), EBADF);
		return;
	}

	sos_iter_free(iter);
	dsosd_handle_free(client, msg->iter_handle);

	dsosd_debug("ep %d msg %p len %d iter %p/%p\n", ep, msg, len, msg->iter_handle, iter);

	dsosd_req_complete_with_status(client, DSOSD_MSG_ITERATOR_CLOSE_RESP, msg->hdr.id,
				       sizeof(dsosd_msg_iterator_close_resp_t), 0);
}

void rpc_handle_iterator_new(zap_ep_t ep, dsosd_msg_iterator_new_req_t *msg, size_t len)
{
	sos_schema_t	schema;
	sos_attr_t	attr;
	sos_iter_t	iter;
	dsosd_req_t	*req;
	dsosd_client_t	*client = (dsosd_client_t *)zap_get_ucontext(ep);

	req = dsosd_req_new(client, DSOSD_MSG_ITERATOR_NEW_RESP, msg->hdr.id,
			    sizeof(dsosd_msg_iterator_new_resp_t));

	schema = dsosd_handle_to_ptr(client, msg->schema_handle);
	if (!schema) {
		req->resp->u.hdr.status = EBADF;
		req->resp->u.hdr.flags  = 0;
		dsosd_req_complete(req, sizeof(dsosd_msg_iterator_new_resp_t));
		return;
	}
	attr = sos_schema_attr_by_id(schema, msg->attr_id);

	iter = sos_attr_iter_new(attr);
	if (iter)
		req->resp->u.iterator_new_resp.iter_handle = dsosd_ptr_to_handle(client, iter);
	else
		req->resp->u.hdr.status = ENOENT;

	dsosd_debug("ep %d msg %p len %d schema %p/%p attr %p iter %pd\n",
		    ep, msg, len, msg->schema_handle, schema, attr, iter);

	dsosd_req_complete(req, sizeof(dsosd_msg_iterator_new_resp_t));
}

void rpc_handle_iterator_step(zap_ep_t ep, dsosd_msg_iterator_step_req_t *msg, size_t len)
{
	int		key_len = 0, ret;
	size_t		buf_len;
	char		*buf, *key_data;
	sos_key_t	key = NULL;
	sos_iter_t	iter;
	dsosd_req_t	*req;
	sos_obj_t	sos_obj = NULL;
	dsosd_client_t	*client = (dsosd_client_t *)zap_get_ucontext(ep);

	if (msg->data_len) {
		buf     = msg->data;
		buf_len = msg->data_len;
		key_len = deserialize_buf(&key_data, &buf, &buf_len);
		key     = sos_key_new(key_len);
		sos_key_set(key, key_data, key_len);
	}

	iter = dsosd_handle_to_ptr(client, msg->iter_handle);
	if (!iter) {
		dsosd_req_complete_with_status(client, DSOSD_MSG_ITERATOR_STEP_RESP, msg->hdr.id,
					       sizeof(dsosd_msg_iterator_step_resp_t), EBADF);
		return;
	}
	switch (msg->op) {
	    case DSOSD_MSG_ITER_OP_BEGIN:
		ret = sos_iter_begin(iter);
		break;
	    case DSOSD_MSG_ITER_OP_END:
		ret = sos_iter_end(iter);
		break;
	    case DSOSD_MSG_ITER_OP_NEXT:
		ret = sos_iter_next(iter);
		break;
	    case DSOSD_MSG_ITER_OP_PREV:
		ret = sos_iter_prev(iter);
		break;
	    case DSOSD_MSG_ITER_OP_FIND:
		ret = sos_iter_find(iter, key);
		break;
	    default:
		ret = EINVAL;
		break;
	}
	if (!ret) {
		sos_obj = sos_iter_obj(iter);
		if (!sos_obj)
			ret = ENOENT;
	}
	dsosd_debug("ep %d op %d iter %p/%p key %p key_len %d ret %d\n", ep, msg->op,
		    msg->iter_handle, iter, key, key_len, ret);

	if (sos_obj)
		dsosd_req_complete_with_obj(ep, sos_obj, DSOSD_MSG_ITERATOR_STEP_RESP, msg);
	else
		dsosd_req_complete_with_status(client, DSOSD_MSG_ITERATOR_STEP_RESP, msg->hdr.id,
					       sizeof(dsosd_msg_iterator_step_resp_t), ret);
	if (key)
		sos_key_put(key);
}

// taken from https://stackoverflow.com/questions/779875/what-is-the-function-to-replace-string-in-c
// You must free the result if result is non-NULL.
char *str_replace(char *orig, char *rep, char *with)
{
	char *result; // the return string
	char *ins;    // the next insert point
	char *tmp;    // varies
	int len_rep;  // length of rep (the string to remove)
	int len_with; // length of with (the string to replace rep with)
	int len_front; // distance between rep and end of last rep
	int count;    // number of replacements

	// sanity checks and initialization
	if (!orig || !rep)
		return NULL;
	len_rep = strlen(rep);
	if (len_rep == 0)
		return NULL; // empty rep causes infinite loop during count
	if (!with)
		with = "";
	len_with = strlen(with);

	// count the number of replacements needed
	ins = orig;
	for (count = 0; tmp = strstr(ins, rep); ++count) {
		ins = tmp + len_rep;
	}

	tmp = result = malloc(strlen(orig) + (len_with - len_rep) * count + 1);

	if (!result)
		return NULL;

	// first time through the loop, all the variable are set correctly
	// from here on,
	//    tmp points to the end of the result string
	//    ins points to the next occurrence of rep in orig
	//    orig points to the remainder of orig after "end of rep"
	while (count--) {
		ins = strstr(orig, rep);
		len_front = ins - orig;
		tmp = strncpy(tmp, orig, len_front) + len_front;
		tmp = strcpy(tmp, with) + len_with;
		orig += len_front + len_rep; // move to next "end of rep"
	}
	strcpy(tmp, orig);
	return result;
}

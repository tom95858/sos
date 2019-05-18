#include <string.h>
#include "dsos_priv.h"

static void rpc_signal_cb(dsos_req_t *req, size_t len, void *ctxt)
{
	dsosd_msg_t	*resp;

	/*
	 * The req->resp response buffer is invalid after this
	 * function returns, so copy out the data here. The response
	 * typically is small.
	 */
	if (req->resp && len) {
		resp = (dsosd_msg_t *)malloc(len);
		if (!resp)
			dsos_fatal("out of memory\n");
		memcpy(resp, req->resp, len);
	} else
		resp = NULL;

	req->resp = resp;

#ifdef DSOS_DEBUG
	if (resp) {
		dsos_debug("req %p len %d ctxt %p msg %p id %ld "
			   "type %d status %d copied to %p\n",
			   req, len, ctxt, req->msg, resp->u.hdr.id,
			   resp->u.hdr.type, resp->u.hdr.status, resp);
	} else {
		dsos_debug("req %p len %d ctxt %p flushed\n",
			   req, len, ctxt);
	}
#endif
	sem_post(&req->sem);
}

static void rpc_all_signal_cb(dsos_req_all_t *req_all, void *ctxt)
{
	dsos_debug("req_all %p signaling\n", req_all);
	sem_post(&req_all->sem);
}

int dsos_rpc_ping(rpc_ping_in_t *args_inp, rpc_ping_out_t **args_outpp)
{
	int			i, ret;
	dsos_req_all_t		*req_all;
	dsosd_msg_ping_req_t	*msg;
	dsosd_msg_ping_resp_t	*resp;

	req_all = dsos_req_all_new(rpc_all_signal_cb, NULL);

	/* Copy in args to the request messages. */
	for (i = 0; i < g.num_servers; ++i) {
		msg = (dsosd_msg_ping_req_t *)req_all->reqs[i]->msg;
		msg->hdr.type = DSOSD_MSG_PING_REQ;
		strcpy(msg->data, "ping");
	}

	ret = dsos_req_all_submit(req_all, sizeof(dsosd_msg_ping_req_t) + 5);
	if (ret)
		return ret;

	sem_wait(&req_all->sem);

	/* Copy out results from the responses. Caller must free. */
	*args_outpp = (rpc_ping_out_t *)malloc(sizeof(rpc_ping_out_t) * g.num_servers);
	if (!args_outpp)
		dsos_fatal("out of memory\n");
	dsos_err_clear();
	for (i = 0; i < g.num_servers; ++i) {
		resp = (dsosd_msg_ping_resp_t *)req_all->reqs[i]->resp;
		(*args_outpp)[i].tot_num_connects    = resp->tot_num_connects;
		(*args_outpp)[i].tot_num_disconnects = resp->tot_num_disconnects;
		(*args_outpp)[i].tot_num_reqs        = resp->tot_num_reqs;
		(*args_outpp)[i].num_clients         = resp->num_clients;
		dsos_err_set(i, resp->hdr.status);
	}

	dsos_req_all_put(req_all);
	return dsos_err_status();
}

int dsos_rpc_container_new(rpc_container_new_in_t  *args_inp,
			   rpc_container_new_out_t *args_outp)
{
	int				i, ret;
	dsos_req_all_t			*req_all;
	dsosd_msg_container_new_req_t	*msg;
	dsosd_msg_container_new_resp_t	*resp;

	req_all = dsos_req_all_new(rpc_all_signal_cb, NULL);

	/* Copy in args to the request messages. */
	for (i = 0; i < g.num_servers; ++i) {
		msg = (dsosd_msg_container_new_req_t *)req_all->reqs[i]->msg;
		msg->hdr.type = DSOSD_MSG_CONTAINER_NEW_REQ;
		strncpy(msg->path, args_inp->path, sizeof(msg->path));
		msg->mode = args_inp->mode;
	}

	ret = dsos_req_all_submit(req_all, sizeof(dsosd_msg_container_new_req_t));
	if (ret)
		return ret;

	sem_wait(&req_all->sem);

	/* Copy out statuses. No data to copy out. */
	dsos_err_clear();
	for (i = 0; i < g.num_servers; ++i) {
		resp = (dsosd_msg_container_new_resp_t *)req_all->reqs[i]->resp;
		dsos_err_set(i, resp->hdr.status);
	}

	dsos_req_all_put(req_all);
	return dsos_err_status();
}

int dsos_rpc_container_open(rpc_container_open_in_t  *args_inp,
			    rpc_container_open_out_t *args_outp)
{
	int				i, ret;
	dsos_req_all_t			*req_all;
	dsosd_msg_container_open_req_t	*msg;
	dsosd_msg_container_open_resp_t	*resp;

	req_all = dsos_req_all_new(rpc_all_signal_cb, NULL);

	/* Copy in args to the request messages. */
	for (i = 0; i < g.num_servers; ++i) {
		msg = (dsosd_msg_container_open_req_t *)req_all->reqs[i]->msg;
		msg->hdr.type = DSOSD_MSG_CONTAINER_OPEN_REQ;
		strncpy(msg->path, args_inp->path, sizeof(msg->path));
		msg->perms = args_inp->perms;
	}

	ret = dsos_req_all_submit(req_all, sizeof(dsosd_msg_container_open_req_t));
	if (ret)
		return ret;

	sem_wait(&req_all->sem);

	/* Copy out results from the responses. Caller must free. */
	args_outp->handles = (dsosd_handle_t *)malloc(sizeof(dsosd_handle_t) * g.num_servers);
	if (!args_outp->handles)
		dsos_fatal("out of memory\n");
	dsos_err_clear();
	for (i = 0; i < g.num_servers; ++i) {
		resp = (dsosd_msg_container_open_resp_t *)req_all->reqs[i]->resp;
		args_outp->handles[i] = resp->handle;
		dsos_err_set(i, resp->hdr.status);
	}

	dsos_req_all_put(req_all);
	return dsos_err_status();
}

int dsos_rpc_container_close(rpc_container_close_in_t  *args_inp,
			     rpc_container_close_out_t *args_outp)
{
	int					i, ret;
	dsos_req_all_t				*req_all;
	dsosd_msg_container_close_req_t		*msg;
	dsosd_msg_container_close_resp_t	*resp;

	req_all = dsos_req_all_new(rpc_all_signal_cb, NULL);

	/* Copy in args to the request messages. */
	for (i = 0; i < g.num_servers; ++i) {
		msg = (dsosd_msg_container_close_req_t *)req_all->reqs[i]->msg;
		msg->hdr.type = DSOSD_MSG_CONTAINER_CLOSE_REQ;
		msg->handle   = args_inp->handles[i];
	}

	ret = dsos_req_all_submit(req_all, sizeof(dsosd_msg_container_close_req_t));
	if (ret)
		return ret;

	sem_wait(&req_all->sem);

	/* Copy out statuses. No data to copy out. */
	dsos_err_clear();
	for (i = 0; i < g.num_servers; ++i) {
		resp = (dsosd_msg_container_close_resp_t *)req_all->reqs[i]->resp;
		dsos_err_set(i, resp->hdr.status);
	}

	dsos_req_all_put(req_all);
	return dsos_err_status();
}

int dsos_rpc_schema_by_name(rpc_schema_by_name_in_t  *args_inp,
			    rpc_schema_by_name_out_t *args_outp)
{
	int				i, ret;
	dsos_req_all_t			*req_all;
	dsosd_msg_schema_by_name_req_t	*msg;
	dsosd_msg_schema_by_name_resp_t	*resp;

	req_all = dsos_req_all_new(rpc_all_signal_cb, NULL);

	/* Copy in args to the request messages. */
	for (i = 0; i < g.num_servers; ++i) {
		msg = (dsosd_msg_schema_by_name_req_t *)req_all->reqs[i]->msg;
		msg->hdr.type    = DSOSD_MSG_SCHEMA_BY_NAME_REQ;
		msg->cont_handle = args_inp->cont_handles[i];
		strncpy(msg->name, args_inp->name, sizeof(msg->name));
	}

	ret = dsos_req_all_submit(req_all, sizeof(dsosd_msg_schema_by_name_req_t));
	if (ret)
		return ret;

	sem_wait(&req_all->sem);

	/* Copy out results from the responses. Caller must free. */
	args_outp->handles = (dsosd_handle_t *)malloc(sizeof(dsosd_handle_t) * g.num_servers);
	if (!args_outp->handles)
		dsos_fatal("out of memory\n");
	dsos_err_clear();
	for (i = 0; i < g.num_servers; ++i) {
		resp = (dsosd_msg_schema_by_name_resp_t *)req_all->reqs[i]->resp;
		args_outp->handles[i] = resp->handle;
		dsos_err_set(i, resp->hdr.status);
	}
	memcpy(args_outp->templ, resp->templ, sizeof(args_outp->templ));

	dsos_req_all_put(req_all);
	return dsos_err_status();
}

int dsos_rpc_schema_from_template(rpc_schema_from_template_in_t  *args_inp,
				  rpc_schema_from_template_out_t *args_outp)
{
	int					i, ret;
	dsos_req_all_t				*req_all;
	dsosd_msg_schema_from_template_req_t	*msg;
	dsosd_msg_schema_from_template_resp_t	*resp;

	req_all = dsos_req_all_new(rpc_all_signal_cb, NULL);

	/* Copy in args to the request messages. */
	for (i = 0; i < g.num_servers; ++i) {
		msg = (dsosd_msg_schema_from_template_req_t *)req_all->reqs[i]->msg;
		msg->hdr.type = DSOSD_MSG_SCHEMA_FROM_TEMPLATE_REQ;
		memcpy(msg->templ, args_inp->templ, args_inp->len);
	}

	ret = dsos_req_all_submit(req_all, sizeof(dsosd_msg_schema_from_template_req_t));
	if (ret)
		return ret;

	sem_wait(&req_all->sem);

	/* Copy out results from the responses. Caller must free. */
	args_outp->handles = (dsosd_handle_t *)malloc(sizeof(dsosd_handle_t) * g.num_servers);
	if (!args_outp->handles)
		dsos_fatal("out of memory\n");
	dsos_err_clear();
	for (i = 0; i < g.num_servers; ++i) {
		resp = (dsosd_msg_schema_from_template_resp_t *)req_all->reqs[i]->resp;
		args_outp->handles[i] = resp->handle;
		dsos_err_set(i, resp->hdr.status);
	}

	dsos_req_all_put(req_all);
	return dsos_err_status();
}

int dsos_rpc_schema_add(rpc_schema_add_in_t  *args_inp,
			rpc_schema_add_out_t *args_outp)
{
	int				i, ret;
	dsos_req_all_t			*req_all;
	dsosd_msg_schema_add_req_t	*msg;
	dsosd_msg_schema_add_resp_t	*resp;

	req_all = dsos_req_all_new(rpc_all_signal_cb, NULL);

	/* Copy in args to the request messages. */
	for (i = 0; i < g.num_servers; ++i) {
		msg = (dsosd_msg_schema_add_req_t *)req_all->reqs[i]->msg;
		msg->hdr.type      = DSOSD_MSG_SCHEMA_ADD_REQ;
		msg->cont_handle   = args_inp->cont_handles[i];
		msg->schema_handle = args_inp->schema_handles[i];
	}

	ret = dsos_req_all_submit(req_all, sizeof(dsosd_msg_schema_add_req_t));
	if (ret)
		return ret;

	sem_wait(&req_all->sem);

	/* Copy out statuses. No data to copy out. */
	dsos_err_clear();
	for (i = 0; i < g.num_servers; ++i) {
		resp = (dsosd_msg_schema_add_resp_t *)req_all->reqs[i]->resp;
		dsos_err_set(i, resp->hdr.status);
	}

	dsos_req_all_put(req_all);
	return dsos_err_status();
}

int dsos_rpc_part_create(rpc_part_create_in_t  *args_inp,
			 rpc_part_create_out_t *args_outp)
{
	int				i, ret;
	dsos_req_all_t			*req_all;
	dsosd_msg_part_create_req_t	*msg;
	dsosd_msg_part_create_resp_t	*resp;

	req_all = dsos_req_all_new(rpc_all_signal_cb, NULL);

	/* Copy in args to the request messages. */
	for (i = 0; i < g.num_servers; ++i) {
		msg = (dsosd_msg_part_create_req_t *)req_all->reqs[i]->msg;
		msg->hdr.type      = DSOSD_MSG_PART_CREATE_REQ;
		msg->cont_handle   = args_inp->cont_handles[i];
		strncpy(msg->name, args_inp->name, sizeof(msg->name));
		strncpy(msg->path, args_inp->path, sizeof(msg->path));
	}

	ret = dsos_req_all_submit(req_all, sizeof(dsosd_msg_part_create_req_t));
	if (ret)
		return ret;

	sem_wait(&req_all->sem);

	/* Copy out statuses. No data to copy out. */
	dsos_err_clear();
	for (i = 0; i < g.num_servers; ++i) {
		resp = (dsosd_msg_part_create_resp_t *)req_all->reqs[i]->resp;
		dsos_err_set(i, resp->hdr.status);
	}

	dsos_req_all_put(req_all);
	return dsos_err_status();
}

int dsos_rpc_part_find(rpc_part_find_in_t  *args_inp,
		       rpc_part_find_out_t *args_outp)
{
	int				i, ret;
	dsos_req_all_t			*req_all;
	dsosd_msg_part_find_req_t	*msg;
	dsosd_msg_part_find_resp_t	*resp;

	req_all = dsos_req_all_new(rpc_all_signal_cb, NULL);

	/* Copy in args to the request messages. */
	for (i = 0; i < g.num_servers; ++i) {
		msg = (dsosd_msg_part_find_req_t *)req_all->reqs[i]->msg;
		msg->hdr.type      = DSOSD_MSG_PART_FIND_REQ;
		msg->cont_handle   = args_inp->cont_handles[i];
		strncpy(msg->name, args_inp->name, sizeof(msg->name));
	}

	ret = dsos_req_all_submit(req_all, sizeof(dsosd_msg_part_find_req_t));
	if (ret)
		return ret;

	sem_wait(&req_all->sem);

	/* Copy out results from the responses. Caller must free. */
	args_outp->handles = (dsosd_handle_t *)malloc(sizeof(dsosd_handle_t) * g.num_servers);
	if (!args_outp->handles)
		dsos_fatal("out of memory\n");
	dsos_err_clear();
	for (i = 0; i < g.num_servers; ++i) {
		resp = (dsosd_msg_part_find_resp_t *)req_all->reqs[i]->resp;
		args_outp->handles[i] = resp->handle;
		dsos_err_set(i, resp->hdr.status);
	}

	dsos_req_all_put(req_all);
	return dsos_err_status();
}

int dsos_rpc_part_set_state(rpc_part_set_state_in_t  *args_inp,
			    rpc_part_set_state_out_t *args_outp)
{
	int				i, ret;
	dsos_req_all_t			*req_all;
	dsosd_msg_part_set_state_req_t	*msg;
	dsosd_msg_part_set_state_resp_t	*resp;

	req_all = dsos_req_all_new(rpc_all_signal_cb, NULL);

	/* Copy in args to the request messages. */
	for (i = 0; i < g.num_servers; ++i) {
		msg = (dsosd_msg_part_set_state_req_t *)req_all->reqs[i]->msg;
		msg->hdr.type  = DSOSD_MSG_PART_SET_STATE_REQ;
		msg->handle    = args_inp->handles[i];
		msg->new_state = args_inp->new_state;
	}

	ret = dsos_req_all_submit(req_all, sizeof(dsosd_msg_part_set_state_req_t));
	if (ret)
		return ret;

	sem_wait(&req_all->sem);

	/* Copy out statuses. No data to copy out. */
	dsos_err_clear();
	for (i = 0; i < g.num_servers; ++i) {
		resp = (dsosd_msg_part_set_state_resp_t *)req_all->reqs[i]->resp;
		dsos_err_set(i, resp->hdr.status);
	}

	dsos_req_all_put(req_all);
	return dsos_err_status();
}

// This call is asynchronous.
int dsos_rpc_object_create(rpc_object_create_in_t *args_inp)
{
	int				server_id;
	char				*obj_data;
	size_t				obj_sz;
	dsos_obj_t			*obj;
	dsosd_msg_obj_create_req_t	*msg;
	size_t				req_len;
	uint8_t				sha[SHA256_DIGEST_LENGTH];

	obj = args_inp->obj;
	sos_obj_data_get(obj->sos_obj, &obj_data, &obj_sz);

	/* Calculate the owning DSOS server. */
	SHA256(obj->buf, obj_sz, sha);
	server_id = sha[0] % g.num_servers;
	dsos_debug("obj %p obj_sz %d owned by server %d\n", obj, obj_sz, server_id);

	/*
	 * Copy in args to the request message. If the object is in-line,
	 * it already has been placed into msg by the application.
	 */
	msg = (dsosd_msg_obj_create_req_t *)obj->req->msg;
	msg->hdr.type      = DSOSD_MSG_OBJ_CREATE_REQ;
	msg->hdr2.obj_sz   = obj_sz;
	msg->schema_handle = obj->schema->handles[server_id];

	req_len = sizeof(dsosd_msg_obj_create_req_t);
	if (msg->hdr.flags & DSOSD_MSG_IMM)
		req_len += obj_sz;

	/* This can block until resources (SQ credits) are available. */
	return dsos_req_submit(obj->req, &g.conns[server_id], req_len);
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

static char *serialize_buf(const void *v, size_t len, char **pp, size_t *psz)
{
	char	*ret = *pp;

	if (len <= *psz) {
		memcpy(*pp, v, len);
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

void *dsos_rpc_serialize_schema_template(sos_schema_template_t t, void *buf, size_t *psz)
{
	int		i, j;
	uint32_t	*p_attrs_len, *p_joinlist_len;
	char		*p = buf;

	serialize_str(t->name, &p, psz);
	p_attrs_len = (uint32_t *)serialize_uint32(0, &p, psz);
	for (i = 0; t->attrs[i].name; ++i) {
		serialize_str   (t->attrs[i].name, &p, psz);
		serialize_uint32(t->attrs[i].type, &p, psz);
		serialize_uint32(t->attrs[i].size, &p, psz);
		p_joinlist_len = (uint32_t *)serialize_uint32(0, &p, psz);
		if (t->attrs[i].join_list) {
			for (j = 0; j < t->attrs[i].size; ++j)
				serialize_str(t->attrs[i].join_list[j], &p, psz);
			if (*psz >= 0) *p_joinlist_len = j;
		}
		serialize_uint32(t->attrs[i].indexed,  &p, psz);
		serialize_str   (t->attrs[i].idx_type, &p, psz);
		serialize_str   (t->attrs[i].key_type, &p, psz);
		serialize_str   (t->attrs[i].idx_args, &p, psz);
	}
	if (*psz >= 0) {
		*p_attrs_len = i;
		*psz = p - (char *)buf;
		return buf;
	} else {
		return NULL;
	}
}

// Serialize as byte_count (32 bits) followed by attr_data.
void *dsos_rpc_serialize_attr_value(sos_value_t v, void *buf, size_t *psz)
{
	size_t	sz = sos_value_size(v);

	serialize_uint32(sz, buf, psz);

	if (sos_value_is_array(v))
		return serialize_buf(&v->data->array.data, sz, buf, psz);
	else
		return serialize_buf(&v->data->prim, sz, buf, psz);
}

sos_schema_template_t dsos_rpc_deserialize_schema_template(char *buf, size_t len)
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

void dsos_rpc_free_schema_template(sos_schema_template_t t)
{
	int	i;

	for (i = 0; t->attrs[i].name; ++i) {
		if (t->attrs[i].join_list)
			free(t->attrs[i].join_list);
	}
	free(t);
}

static void index_obj_cb(dsos_req_all_t *req_all, void *ctxt)
{
	dsos_obj_t	*obj  = ctxt;

	dsos_debug("obj %p\n", obj);

	obj->req_all = req_all;
	if (obj->cb)
		obj->cb(obj, obj->ctxt);
}

int dsos_rpc_obj_index(rpc_obj_index_in_t *args_inp)
{
	int				i, j;
	size_t				len;
	char				*buf, *p;
	dsos_req_all_t			*req_all;
	dsosd_msg_obj_index_req_t	*msg;
	sos_value_t			v;
	dsos_obj_t			*obj;

	obj = args_inp[0].obj;

	req_all = dsos_req_all_sparse_new(index_obj_cb, obj);

	/*
	 * Copy in args to the request messages. Not every server
	 * is always involved. Skip those where the attribute count
	 * is 0 (there is nothing to send).
	 */
	for (i = 0; i < g.num_servers; ++i) {
		if (args_inp[i].num_attrs == 0)
			continue;  // no RPC for this server
		dsos_req_all_add_server(req_all, i);
		msg = (dsosd_msg_obj_index_req_t *)req_all->reqs[i]->msg;
		msg->hdr.type      = DSOSD_MSG_OBJ_INDEX_REQ;
		msg->hdr.flags     = 0;
		msg->hdr.status    = 0;
		msg->cont_handle   = obj->schema->cont->handles[i];
		msg->schema_handle = obj->schema->handles[i];
		msg->obj_id        = obj->obj_id;
		msg->num_attrs     = args_inp[i].num_attrs;

		// len is what's available in the serialization buffer
		len = DSOSD_MSG_MAX_DATA - sizeof(dsosd_msg_obj_index_req_t);
		buf = msg->data;
		for (j = 0; j < args_inp[i].num_attrs; ++j) {
			v = args_inp[i].attrs[j];
			serialize_uint32(sos_attr_id(v->attr), &buf, &len);
			p = buf;
			if (!dsos_rpc_serialize_attr_value(v, &buf, &len)) {
				dsos_error("attr sz %d too big\n", sos_value_size(v));
				sos_value_put(v);
				sos_value_free(v);
				return E2BIG;
			}
#if 0
			printf("Bo: attr_id %d: ", sos_attr_id(v->attr));
			for (; p < buf; ++p) printf(" %02x", *p & 0xff);
			printf("\n");
			fflush(stdout);
#endif
			sos_value_put(v);
			sos_value_free(v);
		}
		msg->data_len = buf - msg->data;
		dsos_debug("obj_id %08lx%08lx server %d has %d attrs data_len %d\n", obj->obj_id,
			   i, args_inp[i].num_attrs, msg->data_len);
		req_all->reqs[i]->msg_len = sizeof(dsosd_msg_obj_index_req_t) + msg->data_len;
	}

	return dsos_req_all_submit(req_all, 0);
}

int dsos_rpc_obj_find(rpc_obj_find_in_t *args_inp, rpc_obj_find_out_t *args_outp)
{
	int				ret;
	void				*key_data;
	size_t				key_sz;
	size_t				buf_len;
	char				*buf, *p;
	dsos_req_t			*req;
	dsosd_msg_obj_find_req_t	*msg;

	req = dsos_req_new(rpc_signal_cb, NULL);
	if (!req)
		return ENOMEM;

	msg = (dsosd_msg_obj_find_req_t *)req->msg;
	msg->hdr.type      = DSOSD_MSG_OBJ_FIND_REQ;
	msg->hdr.flags     = 0;
	msg->hdr.status    = 0;
	msg->cont_handle   = args_inp->cont_handle;
	msg->schema_handle = args_inp->schema_handle;
	msg->attr_id       = sos_attr_id(args_inp->attr);
	msg->hdr2.obj_va   = args_inp->va;
	msg->hdr2.obj_sz   = args_inp->len;

	key_sz   = sos_key_len(args_inp->key);
	key_data = sos_key_value(args_inp->key);

	// buf_len is what's available in the serialization buffer
	buf_len = DSOSD_MSG_MAX_DATA - sizeof(dsosd_msg_obj_find_req_t);
	buf = msg->data;
	serialize_uint32(key_sz, &buf, &buf_len);
	serialize_buf(key_data, key_sz, &buf, &buf_len);
	msg->data_len = buf - msg->data;

	dsos_debug("cont %p schema %p attr_id %d key_sz %d\n",
		   msg->cont_handle, msg->schema_handle, msg->attr_id, key_sz);

	ret = dsos_req_submit(req, &g.conns[args_inp->server_num],
			      sizeof(dsosd_msg_obj_find_req_t) + msg->data_len);
	if (ret) {
		dsos_error("ret %d\n", ret);
		return ret;
	}

	sem_wait(&req->sem);

	/* Copy out results from the response. */
	if (req->resp->u.hdr.status) {
		dsos_debug("status %d\n", req->resp->u.hdr.status);
		return req->resp->u.hdr.status;
	}
	args_outp->obj_id = req->resp->u.obj_find_resp.obj_id.as_obj_ref;
	dsos_debug("obj_id %08lx%08lx\n", args_outp->obj_id.ref.ods, args_outp->obj_id.ref.obj);

	return 0;
}

int dsos_rpc_obj_get(rpc_obj_get_in_t *args_inp, rpc_obj_get_out_t *args_outp)
{
	int			ret, server_num;
	dsos_req_t		*req;
	dsosd_msg_obj_get_req_t	*msg;

	req = dsos_req_new(rpc_signal_cb, NULL);
	if (!req)
		return ENOMEM;

	msg = (dsosd_msg_obj_get_req_t *)req->msg;
	msg->hdr.type          = DSOSD_MSG_OBJ_GET_REQ;
	msg->hdr.flags         = 0;
	msg->hdr.status        = 0;
	msg->cont_handle       = args_inp->cont_handle;
	msg->obj_id.as_obj_ref = args_inp->obj_id;
	msg->hdr2.obj_va       = args_inp->va;
	msg->hdr2.obj_sz       = args_inp->len;

	ret = dsos_req_submit(req, &g.conns[msg->obj_id.serv],
			      sizeof(dsosd_msg_obj_get_req_t));
	if (ret) {
		dsos_error("ret %d\n", ret);
		return ret;
	}

	sem_wait(&req->sem);

	/* Copy out results from the response. */
	if (req->resp->u.hdr.status) {
		dsos_debug("status %d\n", req->resp->u.hdr.status);
		return req->resp->u.hdr.status;
	}
	args_outp->obj_sz = req->resp->u.hdr2.obj_sz;

	if (req->resp->u.hdr.flags & DSOSD_MSG_IMM)
		memcpy((void *)args_inp->va, req->resp->u.obj_get_resp.data, args_outp->obj_sz);

	dsos_debug("obj_id %08lx%08lx flags %x va %p sz %d\n",
		   args_inp->obj_id.ref.ods, args_inp->obj_id.ref.obj,
		   req->resp->u.hdr.flags, args_inp->va, args_outp->obj_sz);

	return 0;
}

int dsos_rpc_iter_new(rpc_iter_new_in_t *args_inp, rpc_iter_new_out_t *args_outp)
{
	int				i, ret;
	dsos_req_all_t			*req_all;
	dsosd_msg_iterator_new_req_t	*msg;
	dsosd_msg_iterator_new_resp_t	*resp;

	req_all = dsos_req_all_new(rpc_all_signal_cb, NULL);

	/* Copy in args to the request messages. */
	for (i = 0; i < g.num_servers; ++i) {
		msg = (dsosd_msg_iterator_new_req_t *)req_all->reqs[i]->msg;
		msg->hdr.type      = DSOSD_MSG_ITERATOR_NEW_REQ;
		msg->schema_handle = args_inp->schema_handles[i];
		msg->attr_id       = sos_attr_id(args_inp->attr);
	}

	ret = dsos_req_all_submit(req_all, sizeof(dsosd_msg_iterator_new_req_t));
	if (ret)
		return ret;

	sem_wait(&req_all->sem);

	/* Copy out results from the responses. Caller must free. */
	args_outp->handles = (dsosd_handle_t *)malloc(sizeof(dsosd_handle_t) * g.num_servers);
	if (!args_outp->handles)
		dsos_fatal("out of memory\n");
	dsos_err_clear();
	for (i = 0; i < g.num_servers; ++i) {
		resp = (dsosd_msg_iterator_new_resp_t *)req_all->reqs[i]->resp;
		args_outp->handles[i] = resp->iter_handle;
		dsos_err_set(i, resp->hdr.status);
	}

	dsos_req_all_put(req_all);
	return dsos_err_status();
}

int dsos_rpc_iter_close(rpc_iter_close_in_t *args_inp, rpc_iter_close_out_t *args_outp)
{
	int				i, ret;
	dsos_req_all_t			*req_all;
	dsosd_msg_iterator_close_req_t	*msg;
	dsosd_msg_iterator_close_resp_t	*resp;

	req_all = dsos_req_all_new(rpc_all_signal_cb, NULL);

	/* Copy in args to the request messages. */
	for (i = 0; i < g.num_servers; ++i) {
		msg = (dsosd_msg_iterator_close_req_t *)req_all->reqs[i]->msg;
		msg->hdr.type    = DSOSD_MSG_ITERATOR_CLOSE_REQ;
		msg->iter_handle = args_inp->iter_handles[i];
	}

	ret = dsos_req_all_submit(req_all, sizeof(dsosd_msg_iterator_close_req_t));
	if (ret)
		return ret;

	sem_wait(&req_all->sem);

	/* Copy out results from the responses. */
	dsos_err_clear();
	for (i = 0; i < g.num_servers; ++i) {
		resp = (dsosd_msg_iterator_close_resp_t *)req_all->reqs[i]->resp;
		dsos_err_set(i, resp->hdr.status);
	}

	dsos_req_all_put(req_all);
	return dsos_err_status();
}

int dsos_rpc_iter_step_all(rpc_iter_step_all_in_t *args_inp, rpc_iter_step_all_out_t *args_outp)
{
	int				i, ret;
	dsos_req_all_t			*req_all;
	dsosd_msg_iterator_step_req_t	*msg;
	dsosd_msg_iterator_step_resp_t	*resp;

	dsos_debug("op %d\n", args_inp->op);

	req_all = dsos_req_all_new(rpc_all_signal_cb, NULL);

	/* Copy in args to the request messages. */
	for (i = 0; i < g.num_servers; ++i) {
		msg = (dsosd_msg_iterator_step_req_t *)req_all->reqs[i]->msg;
		msg->hdr.type    = DSOSD_MSG_ITERATOR_STEP_REQ;
		msg->op          = args_inp->op;
		msg->iter_handle = args_inp->iter_handles[i];
		msg->hdr2.obj_va = (uint64_t)args_inp->vas[i];
		msg->hdr2.obj_sz = args_inp->obj_sz;
	}

	ret = dsos_req_all_submit(req_all, sizeof(dsosd_msg_iterator_step_req_t));
	if (ret)
		return ret;

	sem_wait(&req_all->sem);

	/* Copy out statuses. No data to copy out. */
	args_outp->found = (int *)calloc(g.num_servers, sizeof(int));
	if (!args_outp->found)
		return ENOMEM;
	dsos_err_clear();
	for (i = 0; i < g.num_servers; ++i) {
		resp = (dsosd_msg_iterator_step_resp_t *)req_all->reqs[i]->resp;
		if (resp->hdr.status == 0) {
			args_outp->found[i] = 1;
			dsos_debug("obj from server %d\n", i);
		}
		else if (resp->hdr.status != ENOENT)
			dsos_err_set(i, resp->hdr.status);
	}

	dsos_req_all_put(req_all);
	return dsos_err_status();
}

int dsos_rpc_iter_step_one(rpc_iter_step_one_in_t *args_inp, rpc_iter_step_one_out_t *args_outp)
{
	int				ret;
	dsos_req_t			*req;
	dsosd_msg_iterator_step_req_t	*msg;
	dsosd_msg_iterator_step_resp_t	*resp;

	req = dsos_req_new(rpc_signal_cb, NULL);

	/* Copy in args to the request message. */
	msg = (dsosd_msg_iterator_step_req_t *)req->msg;
	msg->hdr.type    = DSOSD_MSG_ITERATOR_STEP_REQ;
	msg->op          = args_inp->op;
	msg->iter_handle = args_inp->iter_handle;
	msg->hdr2.obj_va = (uint64_t)args_inp->va;
	msg->hdr2.obj_sz = args_inp->obj_sz;

	ret = dsos_req_submit(req, &g.conns[args_inp->server_num], sizeof(dsosd_msg_iterator_step_req_t));
	if (ret)
		return ret;

	sem_wait(&req->sem);

	/* Copy out status. No data to copy out. */
	args_outp->found = (req->resp->u.hdr.status == 0);

	return 0;
}

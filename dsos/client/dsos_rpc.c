#include <string.h>
#include "dsos_priv.h"

static void rpc_all_signal_cb(dsos_req_all_t *req_all, void *ctxt)
{
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
		memcpy(msg->template, args_inp->template, args_inp->len);
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
int dsos_rpc_object_create(rpc_object_create_in_t  *args_inp)
{
	int				server_id;
	dsos_obj_t			*obj;
	dsosd_msg_obj_create_req_t	*msg;
	size_t				req_len;
	uint8_t				sha[SHA256_DIGEST_LENGTH];

	obj = args_inp->obj;

	/* Calculate the owning DSOS server. */
	SHA256(obj->buf, args_inp->len, sha);
	server_id = sha[0] % g.num_servers;
	dsos_debug("obj %p len %d owned by server %d\n", obj, args_inp->len, server_id);

	/*
	 * Copy in args to the request message. If the object is in-line,
	 * it already has been placed into msg by the application.
	 */
	msg = (dsosd_msg_obj_create_req_t *)obj->req->msg;
	msg->hdr.type      = DSOSD_MSG_OBJ_CREATE_REQ;
	msg->len           = args_inp->len;
	msg->schema_handle = args_inp->schema->handles[server_id];

	req_len = sizeof(dsosd_msg_obj_create_req_t);
	if (msg->hdr.flags & DSOSD_MSG_IMM)
		req_len += args_inp->len;

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

	// XXX strdup the string, and free later. we can't keep a pointer
	// into buf b/c it's part of a req's buffer which won't live forever
	// on 2nd thought: this is ok, since we'll be using the template
	// and done with it before the handler returns (the template gets
	// mapped to a local sos_schema_t handle)

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

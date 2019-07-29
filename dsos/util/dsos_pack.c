#include <stdlib.h>
#include <string.h>
#include "dsos_priv.h"

const char *dsos_rpc_type_to_str(int type)
{
	switch (type) {
	    case DSOS_RPC_CONT_NEW:
		return "DSOS_CONT_NEW";
	    case DSOS_RPC_CONT_OPEN:
		return "DSOS_CONT_OPEN";
	    case DSOS_RPC_CONT_CLOSE:
		return "DSOS_CONT_CLOSE";
	    case DSOS_RPC_ITER_CLOSE:
		return "DSOS_ITER_CLOSE";
	    case DSOS_RPC_ITER_NEW:
		return "DSOS_ITER_NEW";
	    case DSOS_RPC_ITER_STEP:
		return "DSOS_ITER_STEP";
	    case DSOS_RPC_OBJ_CREATE:
		return "DSOS_OBJ_CREATE";
	    case DSOS_RPC_OBJ_GET:
		return "DSOS_OBJ_GET";
	    case DSOS_RPC_OBJ_DELETE:
		return "DSOS_OBJ_DELETE";
	    case DSOS_RPC_PART_CREATE:
		return "DSOS_PART_CREATE";
	    case DSOS_RPC_PART_FIND:
		return "DSOS_PART_FIND";
	    case DSOS_RPC_PART_SET_STATE:
		return "DSOS_PART_SET_STATE";
	    case DSOS_RPC_PING:
		return "DSOS_RPC_PING";
	    case DSOS_RPC_SCHEMA_FROM_TEMPLATE:
		return "DSOS_SCHEMA_FROM_TEMPLATE";
	    case DSOS_RPC_SCHEMA_ADD:
		return "DSOS_SCHEMA_ADD";
	    case DSOS_RPC_SCHEMA_BY_NAME:
		return "DSOS_SCHEMA_BY_NAME";
	    case DSOS_RPC_SCHEMA_BY_ID:
		return "DSOS_SCHEMA_BY_ID";
	    case DSOS_RPC_SCHEMA_FIRST:
		return "DSOS_SCHEMA_FIRST";
	    case DSOS_RPC_SCHEMA_NEXT:
		return "DSOS_SCHEMA_NEXT";
	    case DSOS_RPC_FILTER_NEW:
		return "DSOS_FILTER_NEW";
	    case DSOS_RPC_FILTER_FREE:
		return "DSOS_FILTER_FREE";
	    case DSOS_RPC_FILTER_COND_ADD:
		return "DSOS_FILTER_COND_ADD";
	    case DSOS_RPC_FILTER_STEP:
		return "DSOS_FILTER_STEP";
	    case DSOS_RPC_FILTER_MISS_COUNT:
		return "DSOS_FILTER_MISS_COUNT";
	    case DSOS_RPC_FILTER_FLAGS_GET:
		return "DSOS_FILTER_FLAGS_GET";
	    case DSOS_RPC_FILTER_FLAGS_SET:
		return "DSOS_FILTER_FLAGS_SET";
	    default:
		return "<invalid>";
	}
}

static int handle_overflow(dsos_buf_t *buf, int len)
{
	int	need;
	char	*newbuf;

	if (buf->p == NULL)
		return 1;

	if ((buf->len + len) <= buf->allocated)
		return 0;

	need = buf->len + len;
	while (buf->allocated < need)
		buf->allocated *= 2;

	newbuf = malloc(buf->allocated);
	if (!newbuf) {
		buf->p = NULL;
		return 1;
	}

	memcpy(newbuf, buf->msg, buf->len);
	if (buf->free_fn)
		buf->free_fn(buf->msg);

	buf->msg     = (dsos_msg_t *)newbuf;
	buf->p       = (char *)buf->msg + buf->len;
	buf->free_fn = free;

	return 0;
}

int dsos_pack_u32(dsos_buf_t *buf, uint32_t val)
{
	size_t	len = sizeof(uint32_t);

	if (handle_overflow(buf, len))
		return 1;

	*(uint32_t *)buf->p = val;
	buf->p   += len;
	buf->len += len;
	return 0;
}

uint32_t dsos_unpack_u32(dsos_buf_t *buf)
{
	uint32_t	ret;

	ret = *(uint32_t *)(buf->p);
	buf->p += sizeof(uint32_t);
	return ret;
}

int dsos_pack_u64(dsos_buf_t *buf, uint64_t val)
{
	size_t	len = sizeof(uint64_t);

	if (handle_overflow(buf, len))
		return 1;

	*(uint64_t *)buf->p = val;
	buf->p   += len;
	buf->len += len;
	return 0;
}

uint64_t dsos_unpack_u64(dsos_buf_t *buf)
{
	uint64_t ret = *(uint64_t *)(buf->p);
	buf->p += sizeof(uint64_t);
	return ret;
}

int dsos_pack_str(dsos_buf_t *buf, const char *str)
{
	size_t	len = 0;

	if (str)
		len = strlen(str) + 1;

	if (handle_overflow(buf, len + sizeof(uint32_t)))
		return 1;

	dsos_pack_u32(buf, len);
	if (str)
		strncpy(buf->p, str, len);  // strncpy writes the terminating NULL

	buf->p   += len;
	buf->len += len;

	return 0;
}

char *dsos_unpack_str(dsos_buf_t *buf)
{
	uint32_t	len;
	char		*ret;

	len = dsos_unpack_u32(buf);
	if (len) {
		ret = buf->p;
		buf->p += len;
		return ret;
	} else {
		return NULL;
	}
}

int dsos_pack_buf(dsos_buf_t *buf, void *ptr, int len)
{
	if (handle_overflow(buf, len + sizeof(uint32_t)))
		return 1;

	dsos_pack_u32(buf, len);
	if (len)
		memcpy(buf->p, ptr, len);
	buf->p   += len;
	buf->len += len;
	return 0;
}

void *dsos_unpack_buf(dsos_buf_t *buf, int *plen)
{
	int len = dsos_unpack_u32(buf);
	if (plen)
		*plen = len;
	if (len) {
		char *ret = buf->p;
		buf->p += len;
		return ret;
	} else {
		return NULL;
	}
}

/*
 * Object movement:
 *
 * object-create req	client -> server	flags, (len,va) | buf
 * object-create resp	server -> client	obj_id
 *
 * object-get req	client -> server	(len,va)
 * object-get resp	server -> client	obj_id, flags, [buf]
 *
 * object-find req	client -> servers	(len,va)
 * object-find resp	server -> client	obj_id, flags, [buf]
 *
 * (len,va)      dsos_pack_obj_ptr() / dsos_unpack_obj_ptr()
 * buf           dsos_pack_obj()     / dsos_unpack_obj()
 * obj_id        dsos_pack_obj_id()  / dsos_unpack_obj_id()
 */

int dsos_pack_fits(dsos_buf_t *buf, int len)
{
	return (buf->p + len) <= ((char *)buf->msg + buf->allocated);
}

int dsos_pack_obj_needs(sos_obj_t obj)
{
	char		*obj_data;
	size_t		obj_sz;

	sos_obj_data_get(obj, &obj_data, &obj_sz);

	return obj_sz + sizeof(uint32_t);
}

int dsos_pack_obj(dsos_buf_t *buf, sos_obj_t obj)
{
	char		*obj_data;
	size_t		obj_sz;

	sos_obj_data_get(obj, &obj_data, &obj_sz);

	if (handle_overflow(buf, obj_sz + sizeof(uint32_t)))
		return 1;

	dsos_pack_buf(buf, obj_data, obj_sz);
	return 0;
}

int dsos_unpack_obj(dsos_buf_t *buf, sos_obj_t obj)
{
	char		*msg_data, *obj_data;
	int		len;
	size_t		obj_sz;

	sos_obj_data_get(obj, &obj_data, &obj_sz);

	msg_data = dsos_unpack_buf(buf, &len);

	if ((len > obj_sz) || (len > buf->allocated))
		return 1;

	memcpy(obj_data, msg_data, len);
	return 0;
}

int dsos_pack_obj_ptr(dsos_buf_t *buf, sos_obj_t obj)
{
	char		*obj_data;
	size_t		obj_sz;

	sos_obj_data_get(obj, &obj_data, &obj_sz);

	return dsos_pack_u64(buf, (uint64_t)obj_sz) |
	       dsos_pack_u64(buf, (uint64_t)obj_data);
}

uint64_t dsos_unpack_obj_ptr(dsos_buf_t *buf, uint64_t *plen)
{
	*plen = dsos_unpack_u64(buf);
	return  dsos_unpack_u64(buf);
}

int dsos_pack_obj_id(dsos_buf_t *buf, sos_obj_ref_t obj_id)
{
	return dsos_pack_u64(buf, obj_id.ref.ods) |
	       dsos_pack_u64(buf, obj_id.ref.obj);
}

sos_obj_ref_t dsos_unpack_obj_id(dsos_buf_t *buf)
{
	sos_obj_ref_t	ref;

	ref.ref.ods = dsos_unpack_u64(buf);
	ref.ref.obj = dsos_unpack_u64(buf);

	return ref;
}

int dsos_pack_handle(dsos_buf_t *buf, dsos_handle_t handle)
{
	return dsos_pack_u64(buf, (uint64_t)handle);
}

dsos_handle_t dsos_unpack_handle(dsos_buf_t *buf)
{
	return (dsos_handle_t)dsos_unpack_u64(buf);
}

int dsos_pack_key(dsos_buf_t *buf, sos_key_t key)
{
	if (key)
		return dsos_pack_buf(buf, sos_key_value(key), sos_key_len(key));
	else
		return dsos_pack_buf(buf, NULL, 0);
}

sos_key_t dsos_unpack_key(dsos_buf_t *buf)
{
	int		len;
	void		*p;
	sos_key_t	key = NULL;

	p = dsos_unpack_buf(buf, &len);
	if (p) {
		key = sos_key_new(len);
		sos_key_set(key, p, len);
	}
	return key;
}

int dsos_pack_schema(dsos_buf_t *buf, sos_schema_t schema)
{
	int			i, ret;
	sos_attr_t		attr, join_attr;
	sos_schema_data_t	data = schema->data;

	ret  = dsos_pack_str(buf, schema->data->name);
	ret |= dsos_pack_u32(buf, schema->data->attr_cnt);
	TAILQ_FOREACH(attr, &schema->attr_list, entry) {
		ret |= dsos_pack_str(buf, attr->data->name);
		ret |= dsos_pack_u32(buf, attr->data->type);
		if (attr->data->el_sz)
			ret |= dsos_pack_u32(buf, attr->data->count);
		else
			ret |= dsos_pack_u32(buf, attr->data->size);
		if (attr->ext_ptr) {
			ret |= dsos_pack_u32(buf, attr->ext_ptr->count);
			for (i = 0; i < attr->ext_ptr->count; ++i) {
				join_attr = sos_schema_attr_by_id(schema,
								  attr->ext_ptr->data.uint32_[i]);
				ret |= dsos_pack_str(buf, sos_attr_name(join_attr));
			}
		} else {
			ret |= dsos_pack_u32(buf, 0);
		}
		ret |= dsos_pack_u32(buf, attr->data->indexed);
		ret |= dsos_pack_str(buf, attr->idx_type);
		ret |= dsos_pack_str(buf, attr->key_type);
		ret |= dsos_pack_str(buf, attr->idx_args);
	}
	return ret;
}

sos_schema_t dsos_unpack_schema(dsos_buf_t *buf)
{
	int			i, j;
	char			*name;
	uint32_t		num_attrs, num_join_attrs;
	sos_schema_t		schema;
	sos_schema_template_t	t;

	name      = dsos_unpack_str(buf);
	num_attrs = dsos_unpack_u32(buf);

	t = (sos_schema_template_t)dsos_malloc(sizeof(struct sos_schema_template) +
					       sizeof(struct sos_schema_template_attr) * (num_attrs+1));
	t->name = name;
	for (i = 0; i < num_attrs; ++i) {
		t->attrs[i].name = dsos_unpack_str(buf);
		t->attrs[i].type = dsos_unpack_u32(buf);
		t->attrs[i].size = dsos_unpack_u32(buf);
		num_join_attrs   = dsos_unpack_u32(buf);
		t->attrs[i].join_list = NULL;
		if (num_join_attrs) {
			t->attrs[i].join_list = dsos_malloc(sizeof(char *) * num_join_attrs);
			for (j = 0; j < num_join_attrs; ++j)
				t->attrs[i].join_list[j] = dsos_unpack_str(buf);
			t->attrs[i].size = num_join_attrs;
		}
		t->attrs[i].indexed  = dsos_unpack_u32(buf);
		t->attrs[i].idx_type = dsos_unpack_str(buf);
		t->attrs[i].key_type = dsos_unpack_str(buf);
		t->attrs[i].idx_args = dsos_unpack_str(buf);
	}
	t->attrs[i].name = NULL;

	schema = sos_schema_from_template(t);

	for (i = 0; t->attrs[i].name; ++i) {
		if (t->attrs[i].join_list)
			free(t->attrs[i].join_list);
	}
	free(t);

	return schema;
}

void dsos_buf_dump(FILE *f, dsos_buf_t *buf, const char *str)
{
	int	i;
	uint8_t	*p = (uint8_t *)buf->msg;

	fprintf(f, "%s buf %p: msg %p len %d allocated %d p %p free %p\n",
		str, buf, buf->msg, buf->len, buf->allocated, buf->p, buf->free_fn);

	for (i = 0; i < buf->len; ++i) {
		if (i && ((i % 16) == 0))
			fprintf(f, "\n");
		fprintf(f, "%02x ", *p++);
	}
	fprintf(f, "\n");
}

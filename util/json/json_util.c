#include <stdarg.h>
#include <assert.h>
#include "json_util.h"

#define JSON_BUF_START_LEN 8192

jbuf_t jbuf_new(void)
{
	jbuf_t jb = malloc(sizeof(*jb) + JSON_BUF_START_LEN);
	if (jb) {
		jb->buf_len = JSON_BUF_START_LEN;
		jb->cursor = 0;
	}
	return jb;
}

void jbuf_free(jbuf_t jb)
{
	free(jb);
}

jbuf_t jbuf_append_va(jbuf_t jb, const char *fmt, va_list ap)
{
	int cnt, space;
 retry:
	space = jb->buf_len - jb->cursor;
	cnt = vsnprintf(&jb->buf[jb->cursor], space, fmt, ap);
	if (cnt > space) {
		space = jb->buf_len + JSON_BUF_START_LEN;
		jb = realloc(jb, space);
		if (jb) {
			jb->buf_len = space;
			goto retry;
		} else {
			return NULL;
		}
	}
	jb->cursor += cnt;
	return jb;
}

jbuf_t jbuf_append_str(jbuf_t jb, const char *fmt, ...)
{
	int cnt, space;
	va_list ap;
	va_start(ap, fmt);
	jb = jbuf_append_va(jb, fmt, ap);
	va_end(ap);
	return jb;
}

jbuf_t jbuf_append_attr(jbuf_t jb, const char *name, const char *fmt, ...)
{
	int cnt, space;
	va_list ap;
	va_start(ap, fmt);
	jb = jbuf_append_str(jb, "\"%s\":", name);
	if (jb)
		jb = jbuf_append_va(jb, fmt, ap);
	va_end(ap);
	return jb;
}

struct json_traverse_s {
	json_traverse_cb_t	cb;
	void			*arg;
};

static int rbt_traverse_cb(struct rbn *rbn, void *ctxt, int level)
{
	struct json_attr_rbn_s *attr_rbn = (struct json_attr_rbn_s *)rbn;
	struct json_traverse_s *arg = ctxt;
	return arg->cb(attr_rbn->attr, arg->arg);
}

int json_attr_traverse(json_entity_t d, json_traverse_cb_t cb, void *arg)
{
	struct json_traverse_s ctxt = {
		.cb  = cb,
		.arg = arg
	};
	assert(d->type == JSON_DICT_VALUE);
	return rbt_traverse(&d->value.dict_->attr_rbt, rbt_traverse_cb, &ctxt);
}

json_entity_t json_attr_find(json_entity_t d, char *name)
{
	struct json_attr_rbn_s *rbn;

	assert (d->type == JSON_DICT_VALUE);
	rbn = (struct json_attr_rbn_s *)rbt_find(&d->value.dict_->attr_rbt, name);
	if (rbn)
		return rbn->attr->value;
	return NULL;
}

static int attr_rbn_cmp_fn(void *tree_key, void *key)
{
	return strcmp(tree_key, key);
}

static json_entity_t json_dict_new(void)
{
	json_dict_t d = malloc(sizeof *d);
	if (d) {
		d->base.type = JSON_DICT_VALUE;
		d->base.value.dict_ = d;
		rbt_init(&d->attr_rbt, attr_rbn_cmp_fn);
		return &d->base;
	}
	return NULL;
}

static json_entity_t json_str_new(const char *s)
{
	json_str_t str = malloc(sizeof *str);
	if (str) {
		str->base.type = JSON_STRING_VALUE;
		str->base.value.str_ = str;
		str->str = strdup(s);
		if (!str->str) {
			free(str);
			return NULL;
		}
		str->str_len = strlen(s);
		return &str->base;
	}
	return NULL;
}

static json_entity_t json_list_new(void)
{
	json_list_t a = malloc(sizeof *a);
	if (a) {
		a->base.type = JSON_LIST_VALUE;
		a->base.value.list_ = a;
		a->item_count = 0;
		TAILQ_INIT(&a->item_list);
		return &a->base;
	}
	return NULL;
}

void json_item_add(json_entity_t a, json_entity_t e)
{
	assert(a->type == JSON_LIST_VALUE);
	a->value.list_->item_count++;
	TAILQ_INSERT_TAIL(&a->value.list_->item_list, e, item_entry);
}

json_entity_t json_item_first(json_entity_t a)
{
	json_entity_t i;
	assert(a->type == JSON_LIST_VALUE);
	i = TAILQ_FIRST(&a->value.list_->item_list);
	return i;
}

json_entity_t json_item_next(json_entity_t a)
{
	return TAILQ_NEXT(a, item_entry);
}

static json_entity_t json_attr_new(json_entity_t name, json_entity_t value)
{
	json_attr_t a = malloc(sizeof *a);
	if (a) {
		a->base.type = JSON_ATTR_VALUE;
		a->base.value.attr_ = a;
		a->name = name;
		a->value = value;
		return &a->base;
	}
	return NULL;
}

json_entity_t json_entity_new(enum json_value_e type, ...)
{
	uint64_t i;
	double d;
	char *s;
	va_list ap;
	json_entity_t e, name, value;

	va_start(ap, type);
	switch (type) {
	case JSON_INT_VALUE:
		e = malloc(sizeof *e);
		if (!e)
			goto out;
		e->type = type;
		i = va_arg(ap, uint64_t);
		e->value.int_ = i;
		break;
	case JSON_BOOL_VALUE:
		e = malloc(sizeof *e);
		if (!e)
			goto out;
		e->type = type;
		i = va_arg(ap, int);
		e->value.bool_ = i;
		break;
	case JSON_FLOAT_VALUE:
		e = malloc(sizeof *e);
		if (!e)
			goto out;
		e->type = type;
		d = va_arg(ap, double);
		e->value.double_ = d;
		break;
	case JSON_STRING_VALUE:
		s = va_arg(ap, char *);
		e = json_str_new(s);
		break;
	case JSON_ATTR_VALUE:
		name = va_arg(ap, json_entity_t);
		value = va_arg(ap, json_entity_t);
		e = json_attr_new(name, value);
		break;
	case JSON_LIST_VALUE:
		e = json_list_new();
		break;
	case JSON_DICT_VALUE:
		e = json_dict_new();
		break;
	case JSON_NULL_VALUE:
		break;
	default:
		assert(0 == "Invalid entity type");
	}
 out:
	va_end(ap);
	return e;
 err:
	free(e);
	goto out;
}

void json_attr_add(json_entity_t d, json_entity_t a)
{
	struct json_attr_rbn_s *rbn;
	json_str_t s = a->value.attr_->name->value.str_;

	assert(d->type == JSON_DICT_VALUE);
	assert(a->type == JSON_ATTR_VALUE);

	rbn = calloc(1, sizeof(struct json_attr_rbn_s));
	if (rbn) {
		rbn_init((struct rbn *)rbn, s->str);
		rbn->attr = a->value.attr_;
		rbt_ins(&d->value.dict_->attr_rbt, (struct rbn *)rbn);
	}
}

static void json_list_free(json_list_t a)
{
	json_entity_t i;
	assert(a->base.type == JSON_LIST_VALUE);
	while (!TAILQ_EMPTY(&a->item_list)) {
		i = TAILQ_FIRST(&a->item_list);
		TAILQ_REMOVE(&a->item_list, i, item_entry);
		json_entity_free(i);
	}
	free(a);
}

static void json_str_free(json_str_t s)
{
	assert(s->base.type == JSON_STRING_VALUE);
	free(s->str);
	free(s);
}

static void json_attr_free(json_attr_t a)
{
	assert(a->base.type == JSON_ATTR_VALUE);
	json_entity_free(a->name);
	json_entity_free(a->value);
	free(a);
}

static void json_dict_free(json_dict_t d)
{
	struct json_attr_rbn_s *rbn;

	rbn = (struct json_attr_rbn_s *)rbt_min(&d->attr_rbt);
	while (rbn) {
		json_attr_free(rbn->attr);
		rbt_del(&d->attr_rbt, (struct rbn *)rbn);
		free(rbn);
		rbn = (struct json_attr_rbn_s *)rbt_min(&d->attr_rbt);
	}
	free(d);
}

void json_entity_free(json_entity_t e)
{
	if (!e)
		return;
	switch (e->type) {
	case JSON_INT_VALUE:
		free(e);
		break;
	case JSON_BOOL_VALUE:
		free(e);
		break;
	case JSON_FLOAT_VALUE:
		free(e);
		break;
	case JSON_STRING_VALUE:
		json_str_free(e->value.str_);
		break;
	case JSON_ATTR_VALUE:
		json_attr_free(e->value.attr_);
		break;
	case JSON_LIST_VALUE:
		json_list_free(e->value.list_);
		break;
	case JSON_DICT_VALUE:
		json_dict_free(e->value.dict_);
		break;
	case JSON_NULL_VALUE:
		free(e);
		break;
	default:
		/* Leak if we're passed garbage */
		return;
	}
}

enum json_value_e json_entity_type(json_entity_t e)
{
	return e->type;
}

int64_t json_value_int(json_entity_t value)
{
	assert(value->type == JSON_INT_VALUE);
	return value->value.int_;
}

int json_value_bool(json_entity_t value)
{
	assert(value->type == JSON_BOOL_VALUE);
	return value->value.bool_;
}

double json_value_float(json_entity_t value)
{
	assert(value->type == JSON_FLOAT_VALUE);
	return value->value.double_;
}

json_str_t json_value_str(json_entity_t value)
{
	assert(value->type == JSON_STRING_VALUE);
	return value->value.str_;
}

json_attr_t json_value_attr(json_entity_t value)
{
	assert(value->type == JSON_ATTR_VALUE);
	return value->value.attr_;
}

json_list_t json_value_list(json_entity_t value)
{
	assert(value->type == JSON_LIST_VALUE);
	return value->value.list_;
}

json_dict_t json_value_dict(json_entity_t value)
{
	assert(value->type == JSON_DICT_VALUE);
	return value->value.dict_;
}

json_str_t json_attr_name(json_entity_t attr)
{
	assert(attr->type == JSON_ATTR_VALUE);
	return attr->value.attr_->name->value.str_;
}

json_entity_t json_attr_value(json_entity_t attr)
{
	assert(attr->type == JSON_ATTR_VALUE);
	return attr->value.attr_->value;
}

size_t json_list_len(json_entity_t list)
{
	assert(list->type == JSON_LIST_VALUE);
	return list->value.list_->item_count;
}

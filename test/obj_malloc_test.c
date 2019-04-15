#include <pthread.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <assert.h>
#include <sos/sos.h>
#include <ods/ods_atomic.h>

struct sos_schema_template schema_template = {
	.name = "obj_malloc_test",
	.attrs = {
		{ .name = "int16", .type = SOS_TYPE_INT16 },
		{ .name = "int32", .type = SOS_TYPE_INT32 },
		{ .name = "int64", .type = SOS_TYPE_INT64 },
		{ .name = "uint16", .type = SOS_TYPE_UINT16 },
		{ .name = "uint32", .type = SOS_TYPE_UINT32 },
		{ .name = "uint64", .type = SOS_TYPE_UINT64 },
		{ .name = "float", .type = SOS_TYPE_FLOAT },
		{ .name = "double", .type = SOS_TYPE_DOUBLE },
		{ .name = "long_double", .type = SOS_TYPE_LONG_DOUBLE },
		{ .name = "timestamp", .type = SOS_TYPE_TIMESTAMP },
		{ .name = "struct", .type = SOS_TYPE_STRUCT, .size = 24 },
		{ .name = "byte_array", .type = SOS_TYPE_BYTE_ARRAY, .size = 32 },
		{ .name = "char_array", .type = SOS_TYPE_CHAR_ARRAY, .size = 32 },
		{ .name = "int16_array", .type = SOS_TYPE_INT16_ARRAY, .size = 32 },
		{ .name = "int32_array", .type = SOS_TYPE_INT32_ARRAY, .size = 32 },
		{ .name = "int64_array", .type = SOS_TYPE_INT64_ARRAY, .size = 32 },
		{ .name = "uint16_array", .type = SOS_TYPE_UINT16_ARRAY, .size = 32 },
		{ .name = "uint32_array", .type = SOS_TYPE_UINT32_ARRAY, .size = 32 },
		{ .name = "uint64_array", .type = SOS_TYPE_UINT64_ARRAY, .size = 32 },
		{ .name = "float_array", .type = SOS_TYPE_FLOAT_ARRAY, .size = 32 },
		{ .name = "double_array", .type = SOS_TYPE_DOUBLE_ARRAY, .size = 32 },
		{ .name = "long_double_array", .type = SOS_TYPE_LONG_DOUBLE_ARRAY, .size = 32 }
	}
};

static sos_obj_t obj;
static sos_schema_t schema;

int initialize_tests(char *test_dir)
{
	int rc;

	schema = sos_schema_from_template(&schema_template);
	if (!schema)
		return errno;

	obj = sos_obj_malloc(schema);
	if (!obj)
		return errno;

	return 0;
}

int finalize_tests(void)
{
	if (obj)
		sos_obj_put(obj);
	return 0;
}

const char *cleanup_path(void)
{
	return NULL;
}

static union sos_value_data_u _a_vd[32];

static int test_value_data(const char *attr_name)
{
	sos_attr_t a = sos_schema_attr_by_name(schema, attr_name);
	if (!a)
		return errno;
	sos_value_data_t a_vd = &_a_vd[0];
	sos_value_data_t vd = sos_obj_attr_data(obj, a, NULL);
	union sos_timestamp_u ts;
	int rc, i;

	switch (sos_attr_type(a)) {
	case SOS_TYPE_INT16:
		sos_obj_attr_value_set(obj, a, -32);
		vd = sos_obj_attr_data(obj, a, NULL);
		return vd->prim.int16_ - -32;
	case SOS_TYPE_INT32:
		sos_obj_attr_value_set(obj, a, -32);
		vd = sos_obj_attr_data(obj, a, NULL);
		return vd->prim.int32_ - -32;
	case SOS_TYPE_INT64:
		sos_obj_attr_value_set(obj, a, -32);
		vd = sos_obj_attr_data(obj, a, NULL);
		return vd->prim.int64_ - -32;
	case SOS_TYPE_UINT16:
		sos_obj_attr_value_set(obj, a, 32);
		vd = sos_obj_attr_data(obj, a, NULL);
		return vd->prim.uint16_ - 32;
	case SOS_TYPE_UINT32:
		sos_obj_attr_value_set(obj, a, 32);
		vd = sos_obj_attr_data(obj, a, NULL);
		return vd->prim.uint32_ - 32;
	case SOS_TYPE_UINT64:
		sos_obj_attr_value_set(obj, a, 32);
		vd = sos_obj_attr_data(obj, a, NULL);
		return vd->prim.int64_ - 32;
	case SOS_TYPE_FLOAT:
		sos_obj_attr_value_set(obj, a, 32.1234);
		vd = sos_obj_attr_data(obj, a, NULL);
		return vd->prim.float_ - 32.1234;
	case SOS_TYPE_DOUBLE:
		sos_obj_attr_value_set(obj, a, 32.1234);
		vd = sos_obj_attr_data(obj, a, NULL);
		return vd->prim.double_ - 32.1234;
	case SOS_TYPE_LONG_DOUBLE:
		sos_obj_attr_value_set(obj, a, (long double)32.1234);
		vd = sos_obj_attr_data(obj, a, NULL);
		return vd->prim.long_double_ - (long double)32.1234;
	case SOS_TYPE_TIMESTAMP:
		ts.fine.usecs = 1234;
		ts.fine.secs = time(NULL);
		sos_obj_attr_value_set(obj, a, ts);
		vd = sos_obj_attr_data(obj, a, NULL);
		return vd->prim.timestamp_.tv.tv_usec - ts.fine.usecs
			+ vd->prim.timestamp_.tv.tv_sec - ts.fine.secs;
	case SOS_TYPE_BYTE_ARRAY:
		sos_obj_attr_value_set(obj, a, 10, "byte_array");
		vd = sos_obj_attr_data(obj, a, NULL);
		return memcmp(vd->array.data.byte_, "byte_array", vd->array.count);
	case SOS_TYPE_CHAR_ARRAY:
		sos_obj_attr_value_set(obj, a, 10, "char_array");
		vd = sos_obj_attr_data(obj, a, NULL);
		return memcmp(vd->array.data.byte_, "char_array", vd->array.count);
	case SOS_TYPE_INT16_ARRAY:
		for (i = 0; i < 32; i++)
			a_vd->array.data.int16_[i] = i;
		sos_obj_attr_value_set(obj, a, 32, a_vd->array.data.int16_);
		vd = sos_obj_attr_data(obj, a, NULL);
		rc = 0;
		for (i = 0; i < 32; i++)
			rc += (a_vd->array.data.int16_[i] - i);
		return rc;
	case SOS_TYPE_INT32_ARRAY:
		for (i = 0; i < 32; i++)
			a_vd->array.data.int32_[i] = i;
		sos_obj_attr_value_set(obj, a, 32, a_vd->array.data.int32_);
		vd = sos_obj_attr_data(obj, a, NULL);
		rc = 0;
		for (i = 0; i < 32; i++)
			rc += (a_vd->array.data.int32_[i] - i);
		return rc;
	case SOS_TYPE_INT64_ARRAY:
		for (i = 0; i < 32; i++)
			a_vd->array.data.int64_[i] = i;
		sos_obj_attr_value_set(obj, a, 32, a_vd->array.data.int64_);
		vd = sos_obj_attr_data(obj, a, NULL);
		rc = 0;
		for (i = 0; i < 32; i++)
			rc += (a_vd->array.data.int64_[i] - i);
		return rc;
		break;
	case SOS_TYPE_UINT16_ARRAY:
		for (i = 0; i < 32; i++)
			a_vd->array.data.uint16_[i] = i;
		sos_obj_attr_value_set(obj, a, 32, a_vd->array.data.uint16_);
		vd = sos_obj_attr_data(obj, a, NULL);
		rc = 0;
		for (i = 0; i < 32; i++)
			rc += (a_vd->array.data.int16_[i] - i);
		return rc;
		break;
	case SOS_TYPE_UINT32_ARRAY:
		for (i = 0; i < 32; i++)
			a_vd->array.data.uint32_[i] = i;
		sos_obj_attr_value_set(obj, a, 32, a_vd->array.data.uint32_);
		vd = sos_obj_attr_data(obj, a, NULL);
		rc = 0;
		for (i = 0; i < 32; i++)
			rc += (a_vd->array.data.uint32_[i] - i);
		return rc;
	case SOS_TYPE_UINT64_ARRAY:
		for (i = 0; i < 32; i++)
			a_vd->array.data.uint64_[i] = i;
		sos_obj_attr_value_set(obj, a, 32, a_vd->array.data.uint64_);
		vd = sos_obj_attr_data(obj, a, NULL);
		rc = 0;
		for (i = 0; i < 32; i++)
			rc += (a_vd->array.data.uint64_[i] - i);
		return rc;
	case SOS_TYPE_FLOAT_ARRAY:
		for (i = 0; i < 32; i++)
			a_vd->array.data.float_[i] = (float)i;
		sos_obj_attr_value_set(obj, a, 32, a_vd->array.data.float_);
		vd = sos_obj_attr_data(obj, a, NULL);
		rc = 0;
		for (i = 0; i < 32; i++)
			rc += (int)(a_vd->array.data.float_[i] - (float)i);
		return rc;
	case SOS_TYPE_DOUBLE_ARRAY:
		for (i = 0; i < 32; i++)
			a_vd->array.data.double_[i] = (double)i;
		sos_obj_attr_value_set(obj, a, 32, a_vd->array.data.double_);
		vd = sos_obj_attr_data(obj, a, NULL);
		rc = 0;
		for (i = 0; i < 32; i++)
			rc += (int)(a_vd->array.data.double_[i] - (double)i);
		return rc;
	case SOS_TYPE_LONG_DOUBLE_ARRAY:
		for (i = 0; i < 32; i++)
			a_vd->array.data.long_double_[i] = (long double)i;
		sos_obj_attr_value_set(obj, a, 32, a_vd->array.data.long_double_);
		vd = sos_obj_attr_data(obj, a, NULL);
		rc = 0;
		for (i = 0; i < 32; i++)
			rc += (int)(a_vd->array.data.long_double_[i] - (long double)i);
		return rc;
	}
	return EINVAL;
}

int test_uint16(void)
{
	return test_value_data("uint16");
}

int test_int16(void)
{
	return test_value_data("int16");
}

int test_uint32(void)
{
	return test_value_data("uint32");
}

int test_int32(void)
{
	return test_value_data("int32");
}

int test_uint64(void)
{
	return test_value_data("uint64");
}

int test_int64(void)
{
	return test_value_data("int64");
}

int test_float(void)
{
	return test_value_data("float");
}

int test_double(void)
{
	return test_value_data("double");
}

int test_long_double(void)
{
	return test_value_data("long_double");
}

int test_byte_array()
{
	return test_value_data("byte_array");
}

int test_char_array()
{
	return test_value_data("char_array");
}

int test_int16_array()
{
	return test_value_data("int16_array");
}

int test_uint16_array()
{
	return test_value_data("uint16_array");
}

int test_int32_array()
{
	return test_value_data("int32_array");
}

int test_uint32_array()
{
	return test_value_data("uint32_array");
}

int test_int64_array()
{
	return test_value_data("int64_array");
}

int test_uint64_array()
{
	return test_value_data("uint64_array");
}

int test_float_array()
{
	return test_value_data("float_array");
}

int test_double_array()
{
	return test_value_data("double_array");
}

int test_long_double_array()
{
	return test_value_data("long_double_array");
}

static const char *attr_list[] = {
	"uint16",
	"int16",
	"uint32",
	"int32",
	"uint64",
	"int64",
	"float",
	"double",
	"long_double",
	"byte_array",
	"char_array",
	"uint16_array",
	"int16_array",
	"uint32_array",
	"int32_array",
	"uint64_array",
	"int64_array",
	"float_array",
	"double_array",
	"long_double_array"
};

int test_zzz_obj_data_get()
{
	char *data;
	size_t size;
	sos_obj_data_get(obj, &data, &size);

	/*
	 * Allocate another memory object. Copy the object we modified
	 * into it, and then test that object
	 */
	sos_obj_t copy_obj = sos_obj_malloc(schema);
	char *copy_data;
	size_t copy_size;
	sos_obj_data_get(copy_obj, &copy_data, &copy_size);

	if (size != copy_size)
		return size - copy_size;

	memcpy(copy_data, data, copy_size);
	sos_obj_put(obj);
	obj = copy_obj;

	int i;
	for (i = 0; i < sizeof(attr_list) / sizeof(attr_list[0]); i++) {
		int rc = test_value_data(attr_list[i]);
		if (rc)
			return rc;
	}
	return 0;
}

static const char *test_list[] = {
	"test_uint16",
	"test_int16",
	"test_uint32",
	"test_int32",
	"test_uint64",
	"test_int64",
	"test_float",
	"test_double",
	"test_long_double",
	"test_byte_array",
	"test_char_array",
	"test_uint16_array",
	"test_int16_array",
	"test_uint32_array",
	"test_int32_array",
	"test_uint64_array",
	"test_int64_array",
	"test_float_array",
	"test_double_array",
	"test_long_double_array",
	"test_zzz_obj_data_get"
};

int test_count(void)
{
	return sizeof(test_list) / sizeof(test_list[0]);
}

const char *test_name(int i)
{
	return test_list[i];
}


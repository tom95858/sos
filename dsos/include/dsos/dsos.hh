#include <string>
#include <exception>
extern "C" {
#include <dsos/dsos.h>
}

namespace dsos {

class Dsos;
class Cont;
class Schema;

class Exception : public std::exception
{
public:
	Exception(int _errno,   std::string _desc);
	Exception(int *_errnos, std::string _desc);
	virtual ~Exception() throw() {}

private:
	int		errno_;
	std::string	desc_;
	int		*errnos_;
};

/*
 * A DSOS object consists of a memory buffer holding its raw data and
 * a schema describing its structure. The goal is to access the object
 * directly from its native binary representation that has been RMAd
 * into a client-side buffer. The schema describes how to carve this
 * buffer up into Value objects, one for each object attribute.
 */

enum class Type
{
	INT16,
	INT32,
	INT64,
	UINT16,
	UINT32,
	UINT64,
	FLOAT,
	DOUBLE,
	// and more...
};

class Value
{
public:
	virtual Type	type();
	virtual Schema	*schema();
};

template <typename T>
class Value_scalar : public Value
{
public:
	T operator * () const;
	T operator * ();
};

template <typename T>
class Value_array : public Value
{
public:
	T operator * () const;
	T operator * ();
};

class Obj
{
public:
	Obj(Schema *schema);
	virtual ~Obj();

	Value& operator [] (int attr_id) const;
	Value& operator [] (int attr_id);
	Value& operator [] (std::string attr_nm) const;
	Value& operator [] (std::string attr_nm);

	void	commit();
};

class Schema
{
public:
	Schema(const char *name, Cont *cont);
	Schema(const char *name, sos_schema_template_t templ, Cont *cont);
	virtual ~Schema();

	Obj		*obj_new();

	dsos_schema_t	*schema;
};

enum class Cont_flags
{
	EXISTS,
	CREATE,
};

class Cont
{
public:
	Cont(const char *path, Cont_flags flags, int mode, Dsos *dsos);
	virtual ~Cont();

	Schema	*schema(const char *name);

	dsos_t	*cont;
};

class Dsos
{
public:
	Dsos(const char *json_config);
	virtual ~Dsos();

	Cont	*cont(const char *path, Cont_flags flags, int mode);
};

};

#if 0

int main()
{
	dsos = new Dsos("config.json");
	if (make_new) {
		cont   = dsos->cont("/tmp/cont.sos", CREATE, 0755);
		schema = cont->schema_new(template);
	} else {
		cont   = dsos->cont("/tmp/cont.sos", EXISTS, 0755);
		schema = cont->schema("test");
	}

	obj = schema->obj_new();
	obj["attr1"] = "string";
	int i = *obj["my_int_attr"];
	obj->commit();
}

#endif

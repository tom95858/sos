#include <dsos/dsos.hh>

using namespace dsos;

Exception::Exception(int _errno, std::string _desc)
{
	errno_  = _errno;
	errnos_ = NULL;
	desc_   = _desc;
}

Exception::Exception(int *_errnos, std::string _desc)
{
	errno_  = 1;
	errnos_ = _errnos;
	desc_   = _desc;
}

Dsos::Dsos(const char *json_config)
{
	int ret = dsos_init(json_config);
	switch (ret) {
	    case ENOENT:
		throw Exception(ret, "could not read json config file");
	    case ENETDOWN:
		throw Exception(ret, "could not load zap transport");
	    case ECONNREFUSED:
		throw Exception(dsos_err_get(), "could not connect to server");
	    case EREMOTE:
		throw Exception(dsos_err_get(), "error mapping or sharing heap");
	}
}

Dsos::~Dsos()
{
	dsos_disconnect();
}

Cont *Dsos::cont(const char *path, Cont_flags flags, int mode)
{
	return new Cont(path, flags, mode, this);
}

Cont::Cont(const char *path, Cont_flags flags, int mode, Dsos *dsos)
{
	if (flags == Cont_flags::CREATE) {
		int ret = dsos_container_new(path, mode);
		if (ret)
			throw Exception(ret, "could not create new container");
	}
	cont = dsos_container_open(path, (sos_perm_t)mode);
	if (!cont)
		throw Exception(EACCES, "could not open container");
}

Cont::~Cont()
{
	dsos_container_close(cont);
}

Schema *Cont::schema(const char *name)
{
	return new Schema(name, this);
}

Schema::Schema(const char *name, Cont *cont)
{
	schema = dsos_schema_by_name(cont->cont, name);
	if (!schema)
		throw Exception(ENOENT, "could not open schema");
}

Schema::Schema(const char *name, sos_schema_template_t templ, Cont *cont)
{
	schema = dsos_schema_from_template(templ);
	if (!schema)
		throw Exception(ENOENT, "could not open schema from template");

	int ret = dsos_schema_add(cont->cont, schema);
	if (ret)
		throw Exception(ret, "could not add schema to container");
}

Obj *Schema::obj_new()
{
}

Schema::~Schema()
{
}

Obj::Obj(Schema *schema)
{
}

Obj::~Obj()
{
}

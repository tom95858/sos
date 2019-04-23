#include <iostream>
#include <dsos/dsos.hh>

using namespace std;
using namespace dsos;

int main(int ac, char *av[])
{
	Dsos	*dsos;
	Cont	*cont;
	Schema	*schema;

	cout << "Bo was here." << endl;

	dsos = new Dsos(av[1]);
	cont = dsos->cont("/tmp/cont.sos", Cont_flags::EXISTS, 0775);
	schema = cont->schema("small");

	Obj obj = Obj(schema);
	obj["attr1"];

	delete cont;

	cout << "and here." << endl;
	return 0;
}

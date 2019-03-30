#include <iostream>
#include <dsos/dsos.hh>

using namespace std;
using namespace dsos;

int main(int ac, char *av[])
{
	Dsos	*dsos;
	Cont	*cont;
	Schema	*schema;
	Obj	*obj;

	cout << "Bo was here.";

	dsos = new Dsos(av[1]);
	cont = dsos->cont("/tmp/cont.sos", Cont_flags::EXISTS, 0775);
	schema = cont->schema("test");

	cout << "and here.";
	return 0;
}

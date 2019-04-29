#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <getopt.h>
#include <time.h>
#include <semaphore.h>
#include <time.h>
#include <assert.h>
#include <zap.h>
#include <openssl/sha.h>
#include <dsos/dsos.h>
#include "dsos_priv.h"

int		num_iters  = 4;
int		sleep_msec = 0;
char		id;
struct timespec	ts;
uint64_t	nsecs;
sem_t		sem;

uint64_t	hash(void *buf, int len);
void		do_obj_creates();

void usage(char *av[])
{
	fprintf(stderr, "usage: %s [options]\n", av[0]);
	fprintf(stderr, "options:\n");
	fprintf(stderr, "  --config=<json_file>   DSOS config (required).\n");
	fprintf(stderr, "  --numiters=<n>         Number to create.\n");
	fprintf(stderr, "  --sleep=<n>            Sleep n msec between iterations\n");
}

int main(int ac, char *av[])
{
	int		c, i, ret;
	char		*config = NULL;

	struct option	lopts[] = {
		{ "config",	required_argument, NULL, 'c' },
		{ "id",	        required_argument, NULL, 'i' },
		{ "numiters",	required_argument, NULL, 'n' },
		{ "sleep",	required_argument, NULL, 's' },
		{ 0,		0,		   0,     0  }
	};

	memset(&g.opts, 0, sizeof(g.opts));
	while ((c = getopt_long_only(ac, av, "c:n:", lopts, NULL)) != -1) {
		switch (c) {
		    case 'c':
			config = strdup(optarg);
			break;
		    case 'i':
			id = *optarg;
			break;
		    case 'n':
			num_iters = atoi(optarg);
			break;
		    case 's':
			sleep_msec = atoi(optarg);
			break;
		    default:
			usage(av);
			exit(0);
		}
	}
	if (!config) {
		fprintf(stderr, "must specify --config\n");
		usage(av);
		exit(1);
	}

	srandom(time(NULL));
	nsecs = sleep_msec * 1000000;
	ts.tv_sec  = nsecs / 1000000000;
	ts.tv_nsec = nsecs % 1000000000;

	if (dsos_init(config)) {
		fprintf(stderr, "could not establish connections to all DSOS servers\n");
		exit(1);
	}

	do_obj_creates();

	dsos_disconnect();
	sleep(1);
}

void obj_cb(dsos_obj_t *obj, void *ctxt)
{
	uint64_t			i = (uintptr_t)ctxt;
	dsosd_msg_obj_create_resp_t	*resp = (dsosd_msg_obj_create_resp_t *)obj->req->resp;

	if (!resp) {
		printf("[%5d] obj %p ctxt %p no response from server\n", getpid(), obj, ctxt);
		return;
	}

	printf("[%5d] obj %d server %d status %d flags %08x obj_id %08lx%08lx len %d\n", getpid(),
	       i, obj->req->conn->server_id, resp->hdr.status, resp->hdr.flags,
	       resp->obj_id.hi,
	       resp->obj_id.lo,
	       resp->len);
	fflush(stdout);

	sem_post(&sem);
}

struct sos_schema_template schema_template = {
	.name = "test",
	.attrs = {
		{ .name = "seq",  .type = SOS_TYPE_UINT64, .indexed = 1 },
		{ .name = "hash", .type = SOS_TYPE_UINT64 },
		{ .name = "data", .type = SOS_TYPE_CHAR_ARRAY, .size = 4000 },
		{ .name = NULL }
	}
};

dsos_t *create_cont(char *path, int perms)
{
	int		i, ret, sz;
	dsos_t		*cont;
	dsos_part_t	*part;
	dsos_schema_t	*schema;

	ret = dsos_container_new(path, perms);
	if (ret) {
		fprintf(stderr, "could not create container: ");
		for (i = 0; i < g.num_servers; ++i)
			fprintf(stderr, "%d ", dsos_err_get()[i]);
		fprintf(stderr, "\n");
		exit(1);
	}

	cont = dsos_container_open(path, perms);
	if (!cont) {
		fprintf(stderr, "could not open container\n");
		exit(1);
	}

	ret = dsos_part_create(cont, "ROOT", NULL);
	if (ret) {
		fprintf(stderr, "could not create partition: ");
		for (i = 0; i < g.num_servers; ++i)
			fprintf(stderr, "%d ", dsos_err_get()[i]);
		fprintf(stderr, "\n");
		exit(1);
	}

	part = dsos_part_find(cont, "ROOT");
	if (!part) {
		fprintf(stderr, "could not find partition: ");
		for (i = 0; i < g.num_servers; ++i)
			fprintf(stderr, "%d ", dsos_err_get()[i]);
		fprintf(stderr, "\n");
		exit(1);
	}

	ret = dsos_part_state_set(part, SOS_PART_STATE_PRIMARY);
	if (ret) {
		fprintf(stderr, "could not set partition state: ");
		for (i = 0; i < g.num_servers; ++i)
			fprintf(stderr, "%d ", dsos_err_get()[i]);
		fprintf(stderr, "\n");
		exit(1);
	}

	schema = dsos_schema_from_template(&schema_template);
	if (!schema) {
		fprintf(stderr, "could not create schema 'test'\n");
		exit(1);
	}

	ret = dsos_schema_add(cont, schema);
	if (ret) {
		fprintf(stderr, "could not add schema 'test': ");
		for (i = 0; i < g.num_servers; ++i)
			fprintf(stderr, "%d ", dsos_err_get()[i]);
		fprintf(stderr, "\n");
		exit(1);
	}

	return cont;
}

void do_obj_creates()
{
	int		i, j, ret, num;
	uint32_t	x;
	char		*mydata, *p;
	dsos_obj_t	*obj;
	dsos_t		*cont;
	dsos_schema_t	*schema;
	sos_attr_t	attr_seq, attr_hash, attr_data;

	printf("opening container\n");
	cont = dsos_container_open("/tmp/cont.sos", 0755);
	if (!cont) {
		printf("creating container\n");
		cont = create_cont("/tmp/cont.sos", 0755);
		if (!cont) {
			fprintf(stderr, "could not create container\n");
			exit(1);
		}
	}
	printf("getting schema\n");
	schema = dsos_schema_by_name(cont, "test");
	if (!schema) {
		fprintf(stderr, "could not open schema 'test'\n");
		exit(1);
	}

	printf("creating objs\n");

	attr_seq = sos_schema_attr_by_name(schema->schema, "seq");
	if (!attr_seq) {
		fprintf(stderr, "could not get attr seq from schema\n");
		exit(1);
	}
	attr_hash = sos_schema_attr_by_name(schema->schema, "hash");
	if (!attr_hash) {
		fprintf(stderr, "could not get attr hash from schema\n");
		exit(1);
	}
	attr_data = sos_schema_attr_by_name(schema->schema, "data");
	if (!attr_data) {
		fprintf(stderr, "could not get attr data from schema\n");
		exit(1);
	}
	mydata = malloc(4000);
	sem_init(&sem, 0, 0);
	num = 0;
	x = 0;
	for (i = 0; i < num_iters; ++i) {
		obj = dsos_obj_alloc(schema, obj_cb, (void *)(uintptr_t)i);
		if (!obj) {
			fprintf(stderr, "could not create object");
			exit(1);
		}
#if 1
		for (p = mydata, j = 0; j < 500; ++j, p += 8)
			sprintf(p, " %06x%c", x++, id);
#else
		strcpy((char *)mydata, "Bo was here.");
#endif
		sos_obj_attr_value_set(obj->sos_obj, attr_seq, num + id);
		num += 10;
		sos_obj_attr_value_set(obj->sos_obj, attr_hash, hash(mydata, 4000));
		sos_obj_attr_value_set(obj->sos_obj, attr_data, 4000, mydata);
		ret = dsos_obj_create(obj);
		if (ret) {
			fprintf(stderr, "dsos_obj_create %d\n", ret);
			exit(1);
		}
		nanosleep(&ts, NULL);
	}
	// Wait until all object-creation callbacks have occurred.
	for (i = 0; i < num_iters; ++i)
		sem_wait(&sem);
	dsos_container_close(cont);
}

uint64_t hash(void *buf, int len)
{
	uint8_t		*p = buf;
	uint64_t	ret = 0;

	while (len--) ret += *p++;
	return ret;
}

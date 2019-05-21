#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
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
int		lookup = 0;
int		server_num;
uint8_t		id;
struct timespec	ts;
uint64_t	nsecs;
sem_t		sem;
sem_t		sem2;
sos_obj_ref_t	*refs;
dsos_t		*cont;
dsos_schema_t	*schema;
sos_attr_t	attr_seq, attr_hash, attr_data;

uint64_t	hash(void *buf, int len);
void		do_obj_creates();
void		do_obj_finds();
void		do_obj_iter();
void		do_init();
void		do_ping();
dsos_t		*create_cont(char *path, int perms);

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
	int		find = 0, iter = 0, create = 0, ping = 0;
	char		*config = NULL;

	struct option	lopts[] = {
		{ "config",	required_argument, NULL, 'c' },
		{ "id",	        required_argument, NULL, 'i' },
		{ "find",       no_argument,       NULL, 'f' },
		{ "create",     no_argument,       NULL, 'o' },
		{ "iter",       no_argument,       NULL, 'l' },
		{ "ping",       required_argument, NULL, 'p' },
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
			id = atoi(optarg) - 1;
			break;
		    case 'o':
			create = 1;
			break;
		    case 'f':
			find = 1;
			break;
		    case 'l':
			iter = 1;
			break;
		    case 'p':
			ping = 1;
			server_num = atoi(optarg);
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

	printf("%d connecting\n", getpid());
	if (dsos_init(config)) {
		fprintf(stderr, "could not establish connections to all DSOS servers\n");
		exit(1);
	}

	if (ping) {
		printf("%d starting pings\n", getpid());
		do_ping();
		printf("%d disconnecting\n", getpid());
		dsos_disconnect();
		sleep(1);
		printf("%d exiting\n", getpid());
		return 0;
	}

	do_init();

	if (create)
		do_obj_creates();
	if (iter)
		do_obj_iter();
	if (find)
		do_obj_finds();

	dsos_container_close(cont);
	dsos_disconnect();
	sleep(1);
}

void do_ping()
{
	int		i, ret;
	struct timespec	beg, end, elapsed;
	uint64_t	nsecs;

	clock_gettime(CLOCK_REALTIME, &beg);
	for (i = 0; i < num_iters; ++i) {
		ret = dsos_ping(server_num);
		if (ret) {
			printf("error %d\n", ret);
			fflush(stdout);
			exit(1);
		}
	}
	clock_gettime(CLOCK_REALTIME, &end);

	if ((end.tv_nsec - beg.tv_nsec)<0) {
		elapsed.tv_sec  = end.tv_sec - beg.tv_sec-1;
		elapsed.tv_nsec = 1000000000 + end.tv_nsec - beg.tv_nsec;
	} else {
		elapsed.tv_sec  = end.tv_sec  - beg.tv_sec;
		elapsed.tv_nsec = end.tv_nsec - beg.tv_nsec;
	}
	nsecs = elapsed.tv_sec * 1000000000 + elapsed.tv_nsec;

	printf("%.0f pings/sec %.1f usecs/ping %.6f secs %09ld nsecs\n",
	       num_iters/(nsecs/1000000000.0),
	       (nsecs/1000.0)/num_iters,
	       nsecs/1000000000.0,
	       nsecs);
	fflush(stdout);
}

void do_init()
{
	cont = dsos_container_open("/tmp/cont.sos", 0755);
	if (!cont) {
		printf("creating container\n");
		cont = create_cont("/tmp/cont.sos", 0755);
		if (!cont) {
			fprintf(stderr, "could not create container\n");
			exit(1);
		}
	}
	schema = dsos_schema_by_name(cont, "test");
	if (!schema) {
		fprintf(stderr, "could not open schema 'test'\n");
		exit(1);
	}
	attr_seq = sos_schema_attr_by_name(schema->sos_schema, "seq");
	if (!attr_seq) {
		fprintf(stderr, "could not get attr seq from schema\n");
		exit(1);
	}
	attr_hash = sos_schema_attr_by_name(schema->sos_schema, "hash");
	if (!attr_hash) {
		fprintf(stderr, "could not get attr hash from schema\n");
		exit(1);
	}
	attr_data = sos_schema_attr_by_name(schema->sos_schema, "data");
	if (!attr_data) {
		fprintf(stderr, "could not get attr data from schema\n");
		exit(1);
	}
}

void idx_cb(dsos_obj_t *obj, void *ctxt)
{
	int				i;
	pid_t				tid;
	uint64_t			obj_serial = (uintptr_t)ctxt;
	dsosd_msg_obj_index_resp_t	*resp;

	tid = (pid_t)syscall(SYS_gettid);
	for (i = 0; i < obj->req_all->num_servers; ++i) {
		if (!obj->req_all->reqs[i])
			continue;
		resp = (dsosd_msg_obj_index_resp_t *)obj->req_all->reqs[i]->resp;
		if (!resp)
			continue;
		if (resp->hdr.status)
			printf("[%5d] obj %d server %d status %d\n", tid, obj_serial,
			       i, resp->hdr.status);
	}

	sem_post(&sem2);
}

void obj_cb(dsos_obj_t *obj, void *ctxt)
{
	int				ret;
	pid_t				tid;
	uint64_t			i = (uintptr_t)ctxt;
	dsosd_msg_obj_create_resp_t	*resp = (dsosd_msg_obj_create_resp_t *)obj->req->resp;

	tid = (pid_t)syscall(SYS_gettid);
	if (!resp) {
		printf("[%5d] obj %p ctxt %p no response from server\n", tid, obj, ctxt);
		return;
	}
#if 0
	printf("[%5d] obj %d server %d status %d flags %08x obj_id %08lx%08lx len %d\n", tid,
	       i, obj->req->conn->server_id, resp->hdr.status, resp->hdr.flags,
	       resp->obj_id.serv,
	       resp->obj_id.ods,
	       resp->len);
	fflush(stdout);
#endif

	refs[i] = resp->obj_id.as_obj_ref;
	sem_post(&sem);
}

struct sos_schema_template schema_template = {
	.name = "test",
	.attrs = {
		{ .name = "seq",  .type = SOS_TYPE_UINT64,     .indexed = 1 },
		{ .name = "hash", .type = SOS_TYPE_UINT64,     .indexed = 0 },
		{ .name = "data", .type = SOS_TYPE_CHAR_ARRAY, .indexed = 0, .size = 1000 },
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
	int		i, ret;
	uint64_t	num;
	char		*mydata;
	dsos_obj_t	*obj;

	mydata = malloc(4001);
	refs = malloc(num_iters * sizeof(*refs));
	sem_init(&sem, 0, 0);
	sem_init(&sem2, 0, 0);
	num = num_iters * id;
	for (i = 0; i < num_iters; ++i) {
		obj = dsos_obj_alloc(schema, obj_cb, (void *)(uintptr_t)i);
		if (!obj) {
			fprintf(stderr, "could not create object");
			exit(1);
		}
		sprintf(mydata, "seq=%08x", num);
		sos_obj_attr_value_set(obj->sos_obj, attr_seq, num);
		sos_obj_attr_value_set(obj->sos_obj, attr_hash, hash(mydata, 400));
		sos_obj_attr_value_set(obj->sos_obj, attr_data, strlen(mydata)+1, mydata);

		ret = dsos_obj_create(obj);
		if (ret) {
			fprintf(stderr, "dsos_obj_create %d\n", ret);
			exit(1);
		}
		sem_wait(&sem);
		printf("obj %d %d %s %d\n", num, num, mydata, hash(mydata,400));
		num += 1;

#if 0
		ret = dsos_obj_index(obj, idx_cb, (void *)(uintptr_t)i);
		if (ret) {
			fprintf(stderr, "err %d indexing obj\n", ret);
			exit(1);
		}
		sem_wait(&sem2);
#endif

		dsos_obj_free(obj);

		nanosleep(&ts, NULL);
	}
#if 0
	// Wait until all object-creation callbacks have occurred.
	for (i = 0; i < num_iters; ++i)
		sem_wait(&sem);
#endif
#if 0
	printf("all objects created:\n");
	for (i = 0; i < num_iters; ++i) {
		printf("\t%08lx%08lx\n", refs[i]);
	}
#endif
}

void do_obj_finds()
{
	int		i;
	uint64_t	num;
	char		*mydata;
	sos_key_t	key;
	sos_obj_t	sos_obj;

	mydata = malloc(4000);
	num = num_iters * id;
	for (i = 0; i < num_iters; ++i) {
		key = sos_key_for_attr(NULL, attr_seq, num);
		sos_obj = dsos_obj_find(schema, attr_seq, key);
		if (sos_obj) {
			char buf1[16], buf2[32];
			sos_obj_attr_to_str(sos_obj, attr_data, mydata, 4000);
			sos_obj_attr_to_str(sos_obj, attr_seq, buf1, 16);
			sos_obj_attr_to_str(sos_obj, attr_hash, buf2, 32);
			printf("obj %d %s %s %s\n", num, buf1, mydata, buf2);
		} else {
			printf("obj %d NOT FOUND\n", num);
			break;
		}
		fflush(stdout);
		sos_obj_put(sos_obj);
		++num;
	}
}

void do_obj_iter()
{
	uint64_t	num;
	char		*mydata;
	sos_obj_t	sos_obj;
	dsos_iter_t	*iter;

	iter = dsos_iter_new(schema, attr_seq);
	if (!iter) {
		printf("could not create iter\n");
		exit(1);
	}
	printf("created dsos iter\n");
	mydata = malloc(4000);
	num = num_iters * id;
	for (sos_obj = dsos_iter_begin(iter); sos_obj; sos_obj = dsos_iter_next(iter)) {
		char buf1[16], buf2[32];
		sos_obj_attr_to_str(sos_obj, attr_data, mydata, 4000);
		sos_obj_attr_to_str(sos_obj, attr_seq, buf1, 16);
		sos_obj_attr_to_str(sos_obj, attr_hash, buf2, 32);
		printf("obj %d %s %s %s\n", num, buf1, mydata, buf2);
		sos_obj_put(sos_obj);
		++num;
		if (--num_iters <= 0) break;
	}
	return;
}

uint64_t hash(void *buf, int len)
{
	uint8_t		*p = buf;
	uint64_t	ret = 0;

	while (len--) ret += *p++;
	return ret;
}

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
int		start_num = 0;
int		sleep_msec = 0;
int		lookup = 0;
int		progress = 0;
int		sequential = 0;
int		local = 0;
int		server_num;
char		*cont_nm = "/tmp/cont.sos";
struct timespec	ts;
uint8_t		id;
uint64_t	nsecs;
sem_t		sem;
sem_t		sem2;
sos_obj_ref_t	*refs;
dsos_t		*cont;
dsos_schema_t	*schema;
sos_attr_t	attr_seq, attr_hash, attr_data, attr_int1, attr_int2;

uint64_t	hash(void *buf, int len);
void		do_obj_creates();
void		do_obj_finds();
void		do_obj_iter();
void		do_obj_iter_finds();
void		do_init();
void		do_local();
void		do_ping();
dsos_t		*create_cont(char *path, int perms);
void		print_elapsed(int num_iters_interval, int num_iters_tot,
			      struct timespec beg, struct timespec last);

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
		{ "find",       no_argument,       NULL, 'f' },
		{ "config",	required_argument, NULL, 'c' },
		{ "cont",	required_argument, NULL, 'C' },
		{ "create",     no_argument,       NULL, 'o' },
		{ "iter",       no_argument,       NULL, 'l' },
		{ "local",      no_argument,       NULL, 'u' },
		{ "numiters",	required_argument, NULL, 'n' },
		{ "ping",       required_argument, NULL, 'p' },
		{ "progress",   no_argument,       NULL, 'g' },
		{ "sequential", no_argument,       NULL, 'q' },
		{ "sleep",	required_argument, NULL, 's' },
		{ "start",	required_argument, NULL, 'S' },
		{ 0,		0,		   0,     0  }
	};

	memset(&g.opts, 0, sizeof(g.opts));
	while ((c = getopt_long_only(ac, av, "c:n:", lopts, NULL)) != -1) {
		switch (c) {
		    case 'c':
			config = strdup(optarg);
			break;
		    case 'C':
			cont_nm = strdup(optarg);
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
		    case 'g':
			progress = 1;
			break;
		    case 'q':
			sequential = 1;
			break;
		    case 'u':
			local = 1;
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
		    case 'S':
			start_num = atoi(optarg);
			break;
		    default:
			usage(av);
			exit(0);
		}
	}

	if (local) {
		do_local();
		return 0;
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

	ret = dsos_init(config);
	if (ret) {
		fprintf(stderr, "err %d connecting to DSOS servers:\n", ret);
		for (i = 0; i < g.num_servers; ++i)
			fprintf(stderr, "%d ", dsos_err_get()[i]);
		fprintf(stderr, "\n");
		return 1;
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
		do_obj_iter_finds();

	dsos_container_close(cont);
	dsos_disconnect();
	sleep(1);
}

void do_ping()
{
	int			i, ret;
	uint64_t		nsecs;
	struct dsos_ping_stats	stats;
	struct timespec		beg, last;

	clock_gettime(CLOCK_REALTIME, &beg);
	clock_gettime(CLOCK_REALTIME, &last);
	for (i = 0; i < num_iters; ++i) {
		ret = dsos_ping(server_num, &stats);
		if (ret) {
			printf("error %d\n", ret);
			fflush(stdout);
			exit(1);
		}
		if (progress && i && ((i % 50000) == 0)) {
			printf("%d/%d conn/disc %d reqs %d clients\n",
			       stats.tot_num_connects,
			       stats.tot_num_disconnects,
			       stats.tot_num_reqs,
			       stats.num_clients);
			print_elapsed(50000, i, beg, last);
			clock_gettime(CLOCK_REALTIME, &last);
		}
	}
	print_elapsed(50000, num_iters, beg, last);
}

void do_init()
{
	cont = dsos_container_open(cont_nm, 0755);
	if (!cont) {
		cont = create_cont(cont_nm, 0755);
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
	attr_int1 = sos_schema_attr_by_name(schema->sos_schema, "int1");
	if (!attr_int1) {
		fprintf(stderr, "could not get attr int1 from schema\n");
		exit(1);
	}
	attr_int2 = sos_schema_attr_by_name(schema->sos_schema, "int2");
	if (!attr_int2) {
		fprintf(stderr, "could not get attr int2 from schema\n");
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

struct sos_schema_template schema_template = {
	.name = "test",
	.attrs = {
		{ .name = "seq",  .type = SOS_TYPE_UINT64,     .indexed = 1 },
		{ .name = "hash", .type = SOS_TYPE_UINT64,     .indexed = 1 },
		{ .name = "int1", .type = SOS_TYPE_UINT64,     .indexed = 1 },
		{ .name = "int2", .type = SOS_TYPE_UINT64,     .indexed = 1 },
		{ .name = "data", .type = SOS_TYPE_CHAR_ARRAY, .indexed = 0, .size = 9000 },
		{ .name = NULL }
	}
};

dsos_t *create_cont(char *path, int perms)
{
	int		i, ret, sz;
	dsos_t		*cont;
	dsos_part_t	*part;
	dsos_schema_t	*schema;

	printf("creating container\n");

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

	printf("container created\n");

	return cont;
}

void obj_cb(dsos_obj_t *obj, void *ctxt)
{
	int				ret;
	pid_t				tid = 0;
	uint64_t			i = (uintptr_t)ctxt;
	dsosd_msg_obj_create_resp_t	*resp = (dsosd_msg_obj_create_resp_t *)obj->req->resp;

//	tid = (pid_t)syscall(SYS_gettid);
	if (!resp) {
		printf("[%5d] obj %p ctxt %p no response from server\n", tid, obj, ctxt);
		return;
	}
#if 0
	printf("[%5d] obj %d server %d status %d flags %08x obj_id %08lx%08lx len %d\n",
	       tid, i,
	       obj->req->conn->server_id, resp->hdr.status, resp->hdr.flags,
	       resp->obj_id.serv, resp->obj_id.ods, resp->len);
	fflush(stdout);
#endif
//	refs[i] = resp->obj_id.as_obj_ref;

	sem_post(&sem);
}

void do_obj_creates()
{
	int		i, ret;
	uint64_t	num;
	char		*mydata;
	dsos_obj_t	*obj;
	struct timespec	beg, end, last;
	uint64_t	nsecs;

	mydata = malloc(4001);
	sem_init(&sem, 0, 0);
	num = start_num;
	clock_gettime(CLOCK_REALTIME, &beg);
	clock_gettime(CLOCK_REALTIME, &last);

	for (i = 0; i < num_iters; ++i) {
		obj = dsos_obj_alloc(schema, obj_cb, (void *)(uintptr_t)i);
		if (!obj) {
			fprintf(stderr, "could not create object %d", i);
			exit(1);
		}

		sprintf(mydata, "seq=%08x", num);
		sos_obj_attr_value_set(obj->sos_obj, attr_seq, num);
		sos_obj_attr_value_set(obj->sos_obj, attr_int1, num);
		sos_obj_attr_value_set(obj->sos_obj, attr_int2, num);
		sos_obj_attr_value_set(obj->sos_obj, attr_hash, hash(mydata, 400));
		sos_obj_attr_value_set(obj->sos_obj, attr_data, strlen(mydata)+1, mydata);
		num += 1;

		ret = dsos_obj_create(obj);
		if (ret) {
			fprintf(stderr, "dsos_obj_create %d\n", ret);
			exit(1);
		}

		dsos_obj_put(obj);

		if (sequential)
			sem_wait(&sem);

		if (progress && i && ((i % 50000) == 0)) {
			print_elapsed(50000, i, beg, last);
			clock_gettime(CLOCK_REALTIME, &last);
		}
	}

	if (!sequential) {
		// Wait until all object-creation callbacks have occurred.
		for (i = 0; i < num_iters; ++i)
			sem_wait(&sem);
	}

	print_elapsed(50000, num_iters, beg, last);
}

void do_obj_finds()
{
	int		i;
	uint64_t	num;
	char		*mydata;
	sos_key_t	key;
	sos_obj_t	sos_obj;

	mydata = malloc(4000);
	num = start_num;
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
	num = start_num;
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
	dsos_iter_close(iter);
}

void do_obj_iter_finds()
{
	int		i;
	uint64_t	num;
	char		*mydata;
	dsos_iter_t	*iter;
	sos_key_t	key;
	sos_obj_t	sos_obj;
	struct timespec	beg, last;

	iter = dsos_iter_new(schema, attr_seq);
	if (!iter) {
		printf("could not create iter\n");
		exit(1);
	}
	printf("created dsos iter\n");
	mydata = malloc(4000);
	num = start_num;
	clock_gettime(CLOCK_REALTIME, &beg);
	clock_gettime(CLOCK_REALTIME, &last);
	for (i = 0; i < num_iters; ++i) {
		key = sos_key_for_attr(NULL, attr_seq, num);
		sos_obj = dsos_iter_find(iter, key);
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
		sos_obj_put(sos_obj);
		++num;
		if (progress && i && ((i % 50000) == 0)) {
			print_elapsed(50000, i, beg, last);
			clock_gettime(CLOCK_REALTIME, &last);
		}
	}
	print_elapsed(50000, num_iters, beg, last);
	dsos_iter_close(iter);
}

uint64_t hash(void *buf, int len)
{
	uint8_t		*p = buf;
	uint64_t	ret = 0;

	while (len--) ret += *p++;
	return ret;
}

/* Do a simple, purely local SOS object-create test. */
void do_local()
{
	int		i, num, ret;
	char		*mydata;
	char		*cont_nm = "/DATA15/rob/cont.sos";
	sos_t		cont;
	sos_part_t	part;
	sos_schema_t	schema;
	sos_attr_t	attr_seq, attr_hash, attr_data, attr_int1, attr_int2;
	struct timespec	beg, last;

	ret = sos_container_new(cont_nm, 0755);
	if (ret) {
		fprintf(stderr, "could not create container err %d\n", ret);
		exit(1);
	}
	cont = sos_container_open(cont_nm, 0755);
	if (!cont) {
		fprintf(stderr, "could not open container\n");
		exit(1);
	}
	ret = sos_part_create(cont, "ROOT", NULL);
	if (ret) {
		fprintf(stderr, "could not create partition err %d\n", ret);
		exit(1);
	}
	part = sos_part_find(cont, "ROOT");
	if (!part) {
		fprintf(stderr, "could not find partition\n");
		exit(1);
	}
	ret = sos_part_state_set(part, SOS_PART_STATE_PRIMARY);
	if (ret) {
		fprintf(stderr, "could not set partition state err %d\n", ret);
		exit(1);
	}
	schema = sos_schema_from_template(&schema_template);
	if (!schema) {
		fprintf(stderr, "could not create schema\n");
		exit(1);
	}
	ret = sos_schema_add(cont, schema);
	if (ret) {
		fprintf(stderr, "could not add schema err %d\n", ret);
		exit(1);
	}
	attr_seq = sos_schema_attr_by_name(schema, "seq");
	if (!attr_seq) {
		fprintf(stderr, "could not find attr 'seq'\n");
		exit(1);
	}
	attr_hash = sos_schema_attr_by_name(schema, "hash");
	if (!attr_hash) {
		fprintf(stderr, "could not find attr 'hash'\n");
		exit(1);
	}
	attr_data = sos_schema_attr_by_name(schema, "data");
	if (!attr_data) {
		fprintf(stderr, "could not find attr 'data'\n");
		exit(1);
	}
	attr_int1 = sos_schema_attr_by_name(schema, "int1");
	if (!attr_int1) {
		fprintf(stderr, "could not find attr 'int1'\n");
		exit(1);
	}
	attr_int2 = sos_schema_attr_by_name(schema, "int2");
	if (!attr_int2) {
		fprintf(stderr, "could not find attr 'int2'\n");
		exit(1);
	}

	mydata = malloc(4001);
	num = start_num;
	clock_gettime(CLOCK_REALTIME, &beg);
	clock_gettime(CLOCK_REALTIME, &last);
	for (i = 0; i < num_iters; ++i) {
		sos_obj_t obj = sos_obj_new(schema);
		if (!obj) {
			fprintf(stderr, "could not create object %d", i);
			exit(1);
		}

		sprintf(mydata, "seq=%08x", num);
		sos_obj_attr_value_set(obj, attr_seq, num);
		sos_obj_attr_value_set(obj, attr_int1, num);
		sos_obj_attr_value_set(obj, attr_int2, num);
		sos_obj_attr_value_set(obj, attr_hash, hash(mydata, 400));
		sos_obj_attr_value_set(obj, attr_data, strlen(mydata)+1, mydata);
		num += 1;

		ret = sos_obj_index(obj);
		if (ret) {
			fprintf(stderr, "sos_obj_index ret %d\n", ret);
			exit(1);
		}

		sos_obj_put(obj);

		if (progress && i && ((i % 50000) == 0)) {
			print_elapsed(50000, i, beg, last);
			clock_gettime(CLOCK_REALTIME, &last);
		}
	}
	print_elapsed(50000, num_iters, beg, last);
}

void print_elapsed(int num_iters_interval, int num_iters_tot,
		   struct timespec beg, struct timespec last)
{
	struct timespec	cur, elapsed_interval, elapsed_tot;
	uint64_t	nsecs_interval, nsecs_tot;

	clock_gettime(CLOCK_REALTIME, &cur);

	if ((cur.tv_nsec - last.tv_nsec) < 0) {
		elapsed_interval.tv_sec  = cur.tv_sec - last.tv_sec-1;
		elapsed_interval.tv_nsec = 1000000000 + cur.tv_nsec - last.tv_nsec;
	} else {
		elapsed_interval.tv_sec  = cur.tv_sec  - last.tv_sec;
		elapsed_interval.tv_nsec = cur.tv_nsec - last.tv_nsec;
	}
	nsecs_interval = elapsed_interval.tv_sec * 1000000000 + elapsed_interval.tv_nsec;

	if ((cur.tv_nsec - beg.tv_nsec) < 0) {
		elapsed_tot.tv_sec  = cur.tv_sec - beg.tv_sec-1;
		elapsed_tot.tv_nsec = 1000000000 + cur.tv_nsec - beg.tv_nsec;
	} else {
		elapsed_tot.tv_sec  = cur.tv_sec  - beg.tv_sec;
		elapsed_tot.tv_nsec = cur.tv_nsec - beg.tv_nsec;
	}
	nsecs_tot = elapsed_tot.tv_sec * 1000000000 + elapsed_tot.tv_nsec;

	printf("[%5d] %8d: %.0f objs/sec %.1f usecs/obj (this interval), %0.f objs/sec %.1f usecs/obj (cum), %.6f secs\n",
	       getpid(),
	       num_iters_tot,

	       num_iters_interval/(nsecs_interval/1000000000.0),
	       (nsecs_interval/1000.0)/num_iters_interval,

	       num_iters_tot/(nsecs_tot/1000000000.0),
	       (nsecs_tot/1000.0)/num_iters_tot,

	       nsecs_tot/1000000000.0);
	fflush(stdout);
}
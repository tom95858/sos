/*
 * This is a playground for testing and experimentation.
 */

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
int		verbose = 0;
int		server_num;
char		*cont_nm = "/tmp/cont.sos";
struct timespec	sleep_ts;
uint8_t		id;
uint64_t	nsecs;
sem_t		sem;
sem_t		sem2;
sos_obj_ref_t	*refs;
dsos_t		*cont;
sos_schema_t	schema;
sos_attr_t	attrs[100];

uint64_t	hash(void *buf, int len);
void		do_obj_creates();
void		do_obj_deletes();
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
	int		find = 0, iter = 0, loop = 0, create = 0, ping = 0, deletes = 0;
	char		*config = NULL;

	struct option	lopts[] = {
		{ "find",       no_argument,       NULL, 'f' },
		{ "config",	required_argument, NULL, 'c' },
		{ "cont",	required_argument, NULL, 'C' },
		{ "create",     no_argument,       NULL, 'o' },
		{ "deletes",    no_argument,       NULL, 'G' },
		{ "iter",       no_argument,       NULL, 'l' },
		{ "local",      no_argument,       NULL, 'u' },
		{ "loop",       no_argument,       NULL, 'L' },
		{ "numiters",	required_argument, NULL, 'n' },
		{ "ping",       required_argument, NULL, 'p' },
		{ "progress",   optional_argument, NULL, 'g' },
		{ "sequential", no_argument,       NULL, 'q' },
		{ "sleep",	required_argument, NULL, 's' },
		{ "start",	required_argument, NULL, 'S' },
		{ "verbose",	required_argument, NULL, 'v' },
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
		    case 'L':
			loop = 1;
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
		    case 'G':
			deletes = 1;
			break;
		    case 'g':
			if (optarg)
				progress = atoi(optarg);
			else
				progress = 50000;
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
		    case 'v':
			verbose = 1;
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
	sleep_ts.tv_sec  = nsecs / 1000000000;
	sleep_ts.tv_nsec = nsecs % 1000000000;

	ret = dsos_init(config);
	if (ret) {
		dsos_perror("err connecting to DSOS servers\n");
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

	if (create && loop) {
		int i = 1;
		do_init();
		while (1) {
			printf("================== iteration %d ===================\n", i++);
			do_obj_creates();
			do_obj_deletes();
		}
		/*NOTREACHED*/
	}

	do_init();

	if (create)
		do_obj_creates();
	if (deletes)
		do_obj_deletes();
	if (iter)
		do_obj_iter();
	if (find)
		do_obj_iter_finds();

	dsos_container_close(cont, SOS_COMMIT_SYNC);
	dsos_disconnect();
}

void do_ping()
{
	int			i, ret;
	uint64_t		nsecs;
	struct dsos_ping_stats	stats;
	struct timespec		beg, last;

	clock_gettime(CLOCK_REALTIME, &beg);
	clock_gettime(CLOCK_REALTIME, &last);
	for (i = 1; i <= num_iters; ++i) {
		ret = dsos_ping_one(server_num, &stats, 0);
		if (ret) {
			printf("error %d\n", ret);
			fflush(stdout);
			exit(1);
		}
		if (progress && i && ((i % progress) == 0)) {
			printf("%d/%d conn/disc %d reqs %d clients\n",
			       stats.tot_num_connects,
			       stats.tot_num_disconnects,
			       stats.tot_num_reqs,
			       stats.num_clients);
			print_elapsed(progress, i, beg, last);
			clock_gettime(CLOCK_REALTIME, &last);
		}
	}
	if (progress && (num_iters % progress))
		print_elapsed(num_iters % progress, num_iters, beg, last);
}

void do_init()
{
	int	i;

	cont = dsos_container_open(cont_nm, 0755);
	if (!cont) {
		cont = create_cont(cont_nm, 0755);
		if (!cont) {
			dsos_perror("could not create container\n");
			exit(1);
		}
		if (verbose)
			printf("container %s created\n", cont_nm);
	}
	schema = dsos_schema_by_name(cont, "test");
	if (!schema) {
		dsos_perror("could not open schema 'test'\n");
		exit(1);
	}
	for (i = 0; i < 100; ++i) {
		char attr_nm[8];
		snprintf(attr_nm, sizeof(attr_nm), "f%02d", i);
		attrs[i] = sos_schema_attr_by_name(schema, attr_nm);
		if (!attrs[i]) {
			dsos_perror("could not get attr %s from schema\n", attr_nm);
			exit(1);
		}
	}
}

struct sos_schema_template schema_template = {
	.name = "test",
	.attrs = {
		{ .name = "f00",  .type = SOS_TYPE_DOUBLE,     .indexed = 1 },
		{ .name = "f01",  .type = SOS_TYPE_DOUBLE,     .indexed = 1 },
		{ .name = "f02",  .type = SOS_TYPE_DOUBLE,     .indexed = 1 },
		{ .name = "f03",  .type = SOS_TYPE_DOUBLE,     .indexed = 1 },
		{ .name = "f04",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f05",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f06",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f07",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f08",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f09",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f10",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f11",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f12",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f13",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f14",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f15",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f16",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f17",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f18",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f19",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f20",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f21",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f22",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f23",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f24",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f25",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f26",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f27",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f28",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f29",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f30",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f31",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f32",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f33",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f34",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f35",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f36",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f37",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f38",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f39",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f40",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f41",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f42",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f43",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f44",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f45",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f46",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f47",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f48",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f49",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f50",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f51",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f52",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f53",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f54",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f55",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f56",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f57",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f58",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f59",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f60",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f61",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f62",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f63",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f64",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f65",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f66",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f67",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f68",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f69",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f70",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f71",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f72",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f73",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f74",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f75",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f76",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f77",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f78",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f79",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f80",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f81",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f82",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f83",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f84",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f85",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f86",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f87",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f88",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f89",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f90",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f91",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f92",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f93",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f94",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f95",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f96",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f97",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f98",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = "f99",  .type = SOS_TYPE_DOUBLE,     .indexed = 0 },
		{ .name = NULL }
	}
};

dsos_t *create_cont(char *path, int perms)
{
	int		i, ret, sz;
	dsos_t		*cont;
	dsos_part_t	*part;

	if (verbose)
		printf("creating container\n");

	ret = dsos_container_new(path, perms);
	if (ret) {
		dsos_perror("coult not create container\n");
		exit(1);
	}

	cont = dsos_container_open(path, perms);
	if (!cont) {
		dsos_perror("coult not open container\n");
		exit(1);
	}

	ret = dsos_part_create(cont, "ROOT", NULL);
	if (ret) {
		dsos_perror("coult not create partition\n");
		exit(1);
	}

	part = dsos_part_find(cont, "ROOT");
	if (!part) {
		dsos_perror("coult not find partition\n");
		exit(1);
	}

	ret = dsos_part_state_set(part, SOS_PART_STATE_PRIMARY);
	if (ret) {
		dsos_perror("coult not set partition state\n");
		exit(1);
	}

	schema = sos_schema_from_template(&schema_template);
	if (!schema) {
		dsos_perror("coult not create schema 'test'\n");
		exit(1);
	}

	ret = dsos_schema_add(cont, schema);
	if (ret) {
		dsos_perror("coult not add schema 'test'\n");
		exit(1);
	}

	if (verbose)
		printf("container created\n");

	return cont;
}

void obj_cb(sos_obj_t obj, void *ctxt)
{
	sem_post(&sem);
	sos_obj_put(obj);
}

void set_obj(sos_obj_t obj, int num)
{
	int	i;

	for (i = 0; i < 100; ++i)
		sos_obj_attr_value_set(obj, attrs[i], (double)num + i/100.0);
}

void do_obj_creates()
{
	int		i, ret;
	uint64_t	num;
	char		*mydata;
	sos_obj_t	obj;
	struct timespec	beg, end, last;
	uint64_t	nsecs;

	mydata = malloc(4001);
	sem_init(&sem, 0, 0);
	num = start_num;
	clock_gettime(CLOCK_REALTIME, &beg);
	clock_gettime(CLOCK_REALTIME, &last);

	for (i = 1; i <= num_iters; ++i) {
		obj = dsos_obj_alloc(schema);
		if (!obj) {
			dsos_perror("could not create object %d", i);
			exit(1);
		}

		set_obj(obj, num);
		num += 1;
		ret = dsos_obj_create(obj, obj_cb, (void *)(uintptr_t)i);
		if (ret) {
			dsos_perror("dsos_obj_create %d\n", ret);
			exit(1);
		}

		if (sequential)
			sem_wait(&sem);

		if (progress && i && ((i % progress) == 0)) {
			print_elapsed(progress, i, beg, last);
			clock_gettime(CLOCK_REALTIME, &last);
		}

		if (sleep_msec)
			nanosleep(&sleep_ts, NULL);
	}

	if (!sequential)
		dsos_obj_wait_for_all();

	if (progress && (num_iters % progress))
		print_elapsed(num_iters % progress, num_iters, beg, last);
	free(mydata);
}

void do_obj_iter()
{
	uint64_t	num;
	char		*mydata;
	sos_obj_t	obj;
	dsos_iter_t	*iter;

	iter = dsos_attr_iter_new(attrs[0]);
	if (!iter) {
		printf("could not create iter\n");
		exit(1);
	}
	mydata = malloc(4000);
	num = start_num;
	dsos_iter_begin(iter);
	while (obj = dsos_iter_obj(iter)) {
		char buf1[16], buf2[32];
		sos_obj_attr_to_str(obj, attrs[0], buf1, 16);
		sos_obj_attr_to_str(obj, attrs[1], buf2, 32);
		printf("obj %d %s %s\n", num, buf1, buf2);
		sos_obj_put(obj);
		++num;
		if (--num_iters <= 0) break;
		dsos_iter_next(iter);
	}
	dsos_iter_free(iter);
	free(mydata);
}

void do_obj_iter_finds()
{
	int		i;
	uint64_t	num;
	char		*mydata;
	dsos_iter_t	*iter;
	sos_key_t	key;
	sos_obj_t	obj;
	struct timespec	beg, last;

	iter = dsos_attr_iter_new(attrs[0]);
	if (!iter) {
		printf("could not create iter\n");
		exit(1);
	}
	mydata = malloc(4000);
	num = start_num;
	clock_gettime(CLOCK_REALTIME, &beg);
	clock_gettime(CLOCK_REALTIME, &last);
	for (i = 1; i <= num_iters; ++i) {
		key = sos_key_for_attr(NULL, attrs[0], (double)num);
		dsos_iter_find(iter, key);
		obj = dsos_iter_obj(iter);
		if (obj) {
			char buf1[16], buf2[32];
			sos_obj_attr_to_str(obj, attrs[0], buf1, 16);
			sos_obj_attr_to_str(obj, attrs[1], buf2, 32);
			printf("obj %d %s %s\n", num, buf1, buf2);
		} else {
			printf("obj %d NOT FOUND\n", num);
			break;
		}
		sos_obj_put(obj);
		++num;
		if (progress && i && ((i % progress) == 0)) {
			print_elapsed(progress, i, beg, last);
			clock_gettime(CLOCK_REALTIME, &last);
		}
	}
	if (progress && (num_iters % progress))
		print_elapsed(num_iters % progress, num_iters, beg, last);
	dsos_iter_free(iter);
	free(mydata);
}

void do_obj_deletes()
{
	int		i;
	uint64_t	num;
	char		*mydata;
	dsos_iter_t	*iter;
	sos_key_t	key;
	sos_obj_t	obj;
	struct timespec	beg, last;

	iter = dsos_attr_iter_new(attrs[0]);
	if (!iter) {
		printf("could not create iter\n");
		exit(1);
	}
	mydata = malloc(4000);
	num = start_num;
	clock_gettime(CLOCK_REALTIME, &beg);
	clock_gettime(CLOCK_REALTIME, &last);
	for (i = 1; i <= num_iters; ++i) {
		dsos_iter_begin(iter);
		obj = dsos_iter_obj(iter);
		if (!obj) {
			printf("obj %d NOT FOUND\n", num);
			break;
		}
		if (obj && verbose) {
			char buf1[16], buf2[32];
			sos_obj_attr_to_str(obj, attrs[0], buf1, 16);
			sos_obj_attr_to_str(obj, attrs[1], buf2, 32);
			printf("obj %d %s %s\n", num, buf1, buf2);
		}
		dsos_obj_delete(obj);
		sos_obj_put(obj);

		++num;
		if (progress && i && ((i % progress) == 0)) {
			print_elapsed(progress, i, beg, last);
			clock_gettime(CLOCK_REALTIME, &last);
		}
	}
	if (progress && (num_iters % progress))
		print_elapsed(num_iters % progress, num_iters, beg, last);
	dsos_iter_free(iter);
	free(mydata);
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
	for (i = 0; i < 100; ++i) {
		char attr_nm[8];
		snprintf(attr_nm, sizeof(attr_nm), "f%02d", i);
		attrs[i] = sos_schema_attr_by_name(schema, attr_nm);
		if (!attrs[i]) {
			dsos_perror("could not get attr %s from schema\n", attr_nm);
			exit(1);
		}
	}

	mydata = malloc(4001);
	num = start_num;
	clock_gettime(CLOCK_REALTIME, &beg);
	clock_gettime(CLOCK_REALTIME, &last);
	for (i = 1; i <= num_iters; ++i) {
		sos_obj_t obj = sos_obj_new(schema);
		if (!obj) {
			fprintf(stderr, "could not create object %d", i);
			exit(1);
		}

		set_obj(obj, num);
		num += 1;

		ret = sos_obj_index(obj);
		if (ret) {
			fprintf(stderr, "sos_obj_index ret %d\n", ret);
			exit(1);
		}

		sos_obj_put(obj);

		if (progress && i && ((i % progress) == 0)) {
			print_elapsed(progress, i, beg, last);
			clock_gettime(CLOCK_REALTIME, &last);
		}
	}
	if (progress && (num_iters % progress))
		print_elapsed(num_iters % progress, num_iters, beg, last);
	free(mydata);
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

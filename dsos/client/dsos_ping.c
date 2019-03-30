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
int		sleep_msec = 1000;
long 		len = -1;
struct timespec	ts;
uint64_t	nsecs;
sem_t		sem;

void do_obj_creates();
void do_ping_rpc();
void do_ping_all();

void usage(char *av[])
{
	fprintf(stderr, "usage: %s [options]\n", av[0]);
	fprintf(stderr, "options:\n");
	fprintf(stderr, "  --config=<json_file>   DSOS config (required).\n");
	fprintf(stderr, "  --numiters=<n>         Number of pings.\n");
	fprintf(stderr, "  --sleep=<n>            Sleep n msec between pings\n");
}

int main(int ac, char *av[])
{
	int		c, ping=0, i, ret, sz;
	char		*config = NULL;

	struct option	lopts[] = {
		{ "config",	required_argument, NULL, 'c' },
		{ "len",	required_argument, NULL, 'l' },
		{ "numiters",	required_argument, NULL, 'n' },
		{ "ping",	no_argument,       NULL, 'p' },
		{ "sleep",	required_argument, NULL, 's' },
		{ 0,		0,		   0,     0  }
	};

	memset(&g.opts, 0, sizeof(g.opts));
	while ((c = getopt_long_only(ac, av, "c:n:", lopts, NULL)) != -1) {
		switch (c) {
		    case 'c':
			config = strdup(optarg);
			break;
		    case 'l':
			len = atoi(optarg);
			break;
		    case 'n':
			num_iters = atoi(optarg);
			break;
		    case 'p':
			ping = 1;
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

	dsos_init(config);

	if (ping)
		do_ping_rpc();
	else
		do_obj_creates();

	dsos_disconnect();
	printf("exiting after sleep 1...\n");
	sleep(1);
}

void do_ping_rpc()
{
	int		i, ret;
	rpc_ping_in_t	in;
	rpc_ping_out_t	*outp, *p;

	while (num_iters--) {
		ret = dsos_rpc_ping(&in, &outp);
		if (ret) {
			printf("error %d\n", ret);
			return;
		}
		for (i = 0, p = outp; i < g.num_servers; ++i, ++p) {
			printf("server\t#%d\n", i);
			printf("conn\t%d\n",	p->tot_num_connects);
			printf("dconn\t%d\n",	p->tot_num_disconnects);
			printf("reqs\t%d\n",	p->tot_num_reqs);
			printf("clients\t%d\n", p->num_clients);
		}
		free(outp);
		nanosleep(&ts, NULL);
	}
}

void obj_cb(dsos_obj_t *obj, void *ctxt)
{
	dsosd_msg_obj_create_resp_t	*resp = (dsosd_msg_obj_create_resp_t *)obj->req->resp;

	if (!resp) {
		printf("[%5d] obj %p ctxt %p no response from server\n", getpid(), obj, ctxt);
		return;
	}

	printf("[%5d] server %d status %d flags %08x obj_id %ld len %d\n", getpid(),
	       obj->req->conn->server_id, resp->hdr.status, resp->hdr.flags, resp->obj_id, resp->len);
	fflush(stdout);

	int max_inline = obj->req->msg_len_max - sizeof(dsosd_msg_obj_create_req_t);
	if (resp->hdr.flags & 1) {
		// object was sent via immediate message data
		assert(resp->len <= max_inline);
	} else {
		// object was RMA'd from a buffer
		assert(resp->len > max_inline);
	}
	sem_post(&sem);
}

void create_cont(char *path, int perms)
{
	int		i, ret, sz;
	dsos_t		*cont;
	dsos_part_t	*part;
	dsos_schema_t	*schema_big, *schema_small;
	sos_schema_template_t t;

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

	t = calloc(1, sizeof(struct sos_schema_template) + 3*sizeof(struct sos_schema_template_attr));

	t->name = "big";
	t->attrs[0].name    = "attr1";
	t->attrs[0].type    = SOS_TYPE_UINT64;
	t->attrs[0].indexed = 1;
	t->attrs[1].name    = "attr2";
	t->attrs[1].type    = SOS_TYPE_STRUCT;
	t->attrs[1].size    = 4000;
	t->attrs[2].name    = NULL;
	schema_big = dsos_schema_from_template(t);
	if (!schema_big) {
		fprintf(stderr, "could not create schema 'big'\n");
		exit(1);
	}

	ret = dsos_schema_add(cont, schema_big);
	if (ret) {
		fprintf(stderr, "could not add schema 'big': ");
		for (i = 0; i < g.num_servers; ++i)
			fprintf(stderr, "%d ", dsos_err_get()[i]);
		fprintf(stderr, "\n");
		exit(1);
	}

	t->name = "small";
	t->attrs[0].name    = "attr1";
	t->attrs[0].type    = SOS_TYPE_UINT64;
	t->attrs[0].indexed = 1;
	t->attrs[1].name    = NULL;

	schema_small = dsos_schema_from_template(t);
	if (!schema_small) {
		fprintf(stderr, "could not create schema 'small'\n");
		exit(1);
	}

	ret = dsos_schema_add(cont, schema_small);
	if (ret) {
		fprintf(stderr, "could not add schema 'small': ");
		for (i = 0; i < g.num_servers; ++i)
			fprintf(stderr, "%d ", dsos_err_get()[i]);
		fprintf(stderr, "\n");
		exit(1);
	}

	free(t);

	dsos_container_close(cont);
}

void do_obj_creates()
{
	int		i, ret, sz, num = 12666;
	dsos_obj_t	*obj;
	dsos_t		*cont;
	dsos_schema_t	*schema_big, *schema_small;
	sos_schema_template_t t;

	cont = dsos_container_open("/tmp/cont.sos", 0775);
	if (!cont) {
		printf("creating container\n");
		create_cont("/tmp/cont.sos", 0775);
	}
	cont = dsos_container_open("/tmp/cont.sos", 0775);
	if (!cont) {
		fprintf(stderr, "could not open container\n");
		exit(1);
	}
	schema_small = dsos_schema_by_name(cont, "small");
	if (!schema_small) {
		fprintf(stderr, "could not open schema 'small'\n");
		exit(1);
	}
	schema_big = dsos_schema_by_name(cont, "big");
	if (!schema_big) {
		fprintf(stderr, "could not open schema 'big'\n");
		exit(1);
	}

	sem_init(&sem, 0, 4);
	while (num_iters--) {
		if (len < 0)
			sz = random() * (-len-64) / RAND_MAX + 64;
		else
			sz = len;
		sz &= ~1;  // make it even
		sem_wait(&sem);
		obj = dsos_obj_alloc(sz, obj_cb, NULL);
		if (!obj) {
			fprintf(stderr, "could not create object of len %d\n", len);
			exit(1);
		}
		// struct attr parses like a hex dump with no spaces
		// allow 2 bytes at the end of obj->buf for the null byte
		for (i = 0; i < sz/2 - 1; ++i)
			sprintf(obj->buf+i*2, "%02x", num++ & 0xff);
		if (sz > 2000) {
			char c = obj->buf[10];
			sprintf(obj->buf, "%10d", num++);
			obj->buf[10] = c;
//			printf("%d %s\n", sz, obj->buf);
			ret = dsos_obj_create(obj, schema_big, sz);
		} else {
//			printf("%d %s\n", sz, obj->buf);
			ret = dsos_obj_create(obj, schema_small, sz);
		}
		if (ret)
			fprintf(stderr, "dsos_obj_create %d\n", ret);
		nanosleep(&ts, NULL);
	}
	sem_wait(&sem);
	sem_wait(&sem);
	sem_wait(&sem);
	sem_wait(&sem);
	dsos_container_close(cont);
}

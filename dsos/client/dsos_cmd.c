#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <math.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <getopt.h>
#include <semaphore.h>
#include <time.h>
#include <assert.h>
#include <zap.h>
#include <openssl/sha.h>
#include <dsos/dsos.h>
#include "dsos_priv.h"

double			elapsed(struct timespec beg, struct timespec end);
int			do_cont(int ac, char *av[]);
int			do_schema(int ac, char *av[]);
int			do_import(int ac, char *av[]);
int			do_iter(int ac, char *av[]);
int			do_find(int ac, char *av[]);
int			do_migrate(int ac, char *av[]);
int			do_ping(int ac, char *av[]);
int			do_delete(int ac, char *av[]);
void			dump_obj(sos_obj_t sos_obj);
void			dump_schema(sos_schema_t sos_schema);
sos_schema_template_t	parse_schema_template(const char *schema_nm, char *template);
void			print_elapsed(int num_iters_interval, int num_iters_tot,
				      struct timespec beg, struct timespec last);
static struct rbt	migrate_rbt;

void usage(void)
{
	fprintf(stderr, "usage: dsos_cmd <cmd> [options]\n");
	fprintf(stderr, "cmd:\n");
	fprintf(stderr, "  cont      container/partition creation\n");
	fprintf(stderr, "  schema    schema add/dump\n");
	fprintf(stderr, "  import    import CSV data\n");
	fprintf(stderr, "  find      find an object given a key\n");
	fprintf(stderr, "  iter      iterate through a schema/attr\n");
	fprintf(stderr, "  delete    iterate and delete objects\n");
	fprintf(stderr, "  ping      ping one or more servers\n");
}

int main(int ac, char *av[])
{
	int	i, ret;
	char	*config = getenv("DSOS_CONFIG");

	if (ac < 2) {
		usage();
		return 1;
	}
	if (config) {
		ret = dsos_init(config);
		if (ret) {
			dsos_perror("could not connect to all DSOS servers\n");
			return ret;
		}
	} else {
		fprintf(stderr, "must set $DSOS_CONFIG\n");
		return 1;
	}
	if      (!strcmp(av[1], "cont"))    ret = do_cont  (ac-1, av+1);
	else if (!strcmp(av[1], "schema"))  ret = do_schema(ac-1, av+1);
	else if (!strcmp(av[1], "find"))    ret = do_find  (ac-1, av+1);
	else if (!strcmp(av[1], "iter"))    ret = do_iter  (ac-1, av+1);
	else if (!strcmp(av[1], "delete"))  ret = do_delete(ac-1, av+1);
	else if (!strcmp(av[1], "import"))  ret = do_import(ac-1, av+1);
	else if (!strcmp(av[1], "migrate")) ret = do_migrate(ac-1, av+1);
	else if (!strcmp(av[1], "ping"))    ret = do_ping  (ac-1, av+1);
	else {
		usage();
		ret = 1;
	}
	if (!ret)
		dsos_disconnect();
	return ret;
}

/*
 * dsos_cmd cont --create /tmp/cont.sos 755 ROOT
 * dsos_cmd cont --delete /tmp/cont.sos
 */
int do_cont(int ac, char *av[])
{
	int				c, i, mode, ret;
	dsos_t				*cont;
	dsos_part_t			*part;
	enum { NONE,CREATE,DELETE }	op = NONE;

	struct option	lopts[] = {
		{ "create",	no_argument,       NULL, 'c' },
		{ 0,		0,		   0,     0  }
	};

	while ((c = getopt_long_only(ac, av, "cm", lopts, NULL)) != -1) {
		switch (c) {
		    case 'c': op = CREATE; break;
		    default:
usage:
			usage();
			fprintf(stderr, "options:\n");
			fprintf(stderr, "  --create <path> <mode> <part>  Create a container\n");
			return 1;
		}
	}
	if (op == NONE) {
		fprintf(stderr, "must specify --create or --delete\n");
		return 1;
	}

	if (op == CREATE) {
		if ((ac - optind) != 3) {
			usage();
			goto usage;
		}
		if (sscanf(av[optind+1], "%o", &mode) != 1) {
			fprintf(stderr, "invalid mode (must be octal)\n");
			return 1;
		}
		ret = dsos_container_new(av[optind], mode);
		if (ret) {
			dsos_perror("error creating container '%s'\n", av[optind]);
			return ret;
		}
		cont = dsos_container_open(av[optind], mode);
		if (!cont) {
			dsos_perror("error opening container '%s'\n", av[optind]);
			return 1;
		}
		ret = dsos_part_create(cont, av[optind+2], NULL);
		if (ret) {
			dsos_perror("error creating partition '%s'\n", av[optind+2]);
			return ret;
		}
		part = dsos_part_find(cont, av[optind+2]);
		if (!part) {
			dsos_perror("error finding partition '%s'\n", av[optind+2]);
			return 1;
		}
		ret = dsos_part_state_set(part, SOS_PART_STATE_PRIMARY);
		if (ret) {
			dsos_perror("error setting partition state\n");
			return ret;
		}
		dsos_container_close(cont, SOS_COMMIT_SYNC);
	}

	return 0;
}
/*
 * dsos_cmd schema --add --cont /tmp/cont.sos --schema <spec>
 * dsos_cmd schema --dump --cont /tmp/cont.sos --schema <name>
 */
int do_schema(int ac, char *av[])
{
	int			c, i, add = 0, dump = 0, ret;
	char			*cont_nm = NULL, *schema_nm = NULL, *template = NULL;
	dsos_t			*cont;
	sos_schema_t		schema;
	enum { NONE,ADD,DUMP }	op = NONE;
	sos_schema_template_t	sos_templ;

	struct option	lopts[] = {
		{ "add",	no_argument,       NULL, 'a' },
		{ "cont",	required_argument, NULL, 'c' },
		{ "dump",	no_argument,       NULL, 'd' },
		{ "schema",	required_argument, NULL, 's' },
		{ "template",	required_argument, NULL, 't' },
		{ 0,		0,		   0,     0  }
	};

	while ((c = getopt_long_only(ac, av, "ac:ds:", lopts, NULL)) != -1) {
		switch (c) {
		    case 'a': op = ADD;  break;
		    case 'd': op = DUMP; break;
		    case 'c': cont_nm   = strdup(optarg); break;
		    case 's': schema_nm = strdup(optarg); break;
		    case 't': template  = strdup(optarg); break;
		    default:
usage:
			usage();
			fprintf(stderr, "options:\n");
			fprintf(stderr, "  --add              Add schema to container\n");
			fprintf(stderr, "  --dump             Dump schema from container\n");
			fprintf(stderr, "  --cont <path>      Container path\n");
			fprintf(stderr, "  --schema <name>    Schema name\n");
			fprintf(stderr, "  --template <templ> Schema template\n");
			return 1;
		}
	}
	if (op == NONE) {
		fprintf(stderr, "must specify one of --add or --dump\n");
		goto usage;
	}
	if (!cont_nm || !schema_nm) {
		fprintf(stderr, "must specify both --cont and --schema\n");
		goto usage;
	}
	if ((op == ADD) && !template) {
		fprintf(stderr, "must specify both --schema and --template\n");
		goto usage;
	}
	cont = dsos_container_open(cont_nm, 0755);
	if (!cont) {
		dsos_perror("could not open container\n");
		return 1;
	}
	switch (op) {
	    case ADD:
		sos_templ = parse_schema_template(schema_nm, template);
		if (!sos_templ)
			return 1;
		schema = sos_schema_from_template(sos_templ);
		if (!schema) {
                       dsos_perror("could not create schema '%s'\n", schema_nm);
			return 1;
		}
		free(sos_templ);
		ret = dsos_schema_add(cont, schema);
		if (ret) {
                       dsos_perror("could not create schema '%s'\n", schema_nm);
			return 1;
		}
		break;
	    case DUMP:
		schema = dsos_schema_by_name(cont, schema_nm);
		if (!schema) {
                       dsos_perror("could not open schema '%s'\n", schema_nm);
			return 1;
		}
		dump_schema(schema);
		break;
	}
	dsos_container_close(cont, SOS_COMMIT_SYNC);
	return 0;
}

static int import_verbose;

static void obj_cb(sos_obj_t obj, void *ctxt)
{
	if (import_verbose)
		printf("obj_id %lx%lx\n", obj->obj_ref.ref.ods, obj->obj_ref.ref.obj);
}

/*
 * dsos_cmd import --cont /tmp/cont.sos --schema test [file]
 */
int do_import(int ac, char *av[])
{
	int		bufsz, c, i, num_objs, ret;
	int		progress = 0;
	FILE		*fp;
	char		*cont_nm = NULL, *schema_nm = NULL, *buf, *tok;
	dsos_t		*cont;
	sos_schema_t	schema;
	sos_obj_t	obj;
	sos_attr_t	attr;
	sem_t		sem;
	struct timespec	beg, end, last;

	struct option	lopts[] = {
		{ "cont",	required_argument, NULL, 'c' },
		{ "schema",	required_argument, NULL, 's' },
		{ "progress",   optional_argument, NULL, 'g' },
		{ "verbose",	no_argument,       NULL, 'v' },
		{ 0,		0,		   0,     0  }
	};

	while ((c = getopt_long_only(ac, av, "c:s:", lopts, NULL)) != -1) {
		switch (c) {
		    case 'c': cont_nm   = strdup(optarg); break;
		    case 's': schema_nm = strdup(optarg); break;
		    case 'v': import_verbose = 1; break;
		    case 'g':
			if (optarg)
				progress = atoi(optarg);
			else
				progress = 10000;
			break;
		    default:
			usage();
			fprintf(stderr, "options:\n");
			fprintf(stderr, "  --cont <path>      Container path\n");
			fprintf(stderr, "  --schema <name>    Schema name\n");
			fprintf(stderr, "  --progress [n]     Show rate every n objects\n");
			fprintf(stderr, "  --verbose\n");
			return 1;
		}
	}
	if (!cont_nm || !schema_nm) {
		fprintf(stderr, "must specify --cont and --schema\n");
		return 1;
	}
	if (optind < ac) {
		fp = fopen(av[optind], "r");
		if (!fp) {
			fprintf(stderr, "could not open file %s\n", av[optind]);
			return 1;
		}
	} else {
		fp = stdin;
	}

	cont = dsos_container_open(cont_nm, 0755);
	if (!cont) {
		dsos_perror("could not open container\n");
		return 1;
	}
	schema = dsos_schema_by_name(cont, schema_nm);
	if (!schema) {
		dsos_perror("could not open schema '%s'\n", schema_nm);
		return 1;
	}

	bufsz = 1024*1024;
	buf   = malloc(bufsz);
	if (!buf) {
		fprintf(stderr, "out of memory\n");
		return 1;
	}
	sem_init(&sem, 0, 0);
	num_objs = 0;
	clock_gettime(CLOCK_REALTIME, &beg);
	clock_gettime(CLOCK_REALTIME, &last);
	while (fgets(buf, bufsz, fp)) {
		if (buf[strlen(buf)-1] == '\n')
			buf[strlen(buf)-1] = 0;  // chomp
		obj = dsos_obj_alloc(schema);
		if (!obj) {
			dsos_perror("could not create object %d\n", i);
			exit(1);
		}
		for (i = 0, tok = strtok(buf, ","); tok; tok = strtok(NULL, ","), ++i) {
			attr = sos_schema_attr_by_id(schema, i);
			if (!attr) {
				fprintf(stderr, "could not get attribute #%d\n", i);
				return 1;
			}
			ret = sos_obj_attr_from_str(obj, attr, tok, NULL);
			if (ret) {
				fprintf(stderr, "error setting attribute %s\n", sos_attr_name(attr));
				return 1;
			}
		}
		ret = dsos_obj_create(obj, obj_cb, &sem);
		if (ret) {
			dsos_perror("error %d creating DSOS object\n", ret);
			return 1;
		}
		sos_obj_put(obj);
		++num_objs;
		if (progress && num_objs && ((num_objs % progress) == 0)) {
			print_elapsed(progress, num_objs, beg, last);
			clock_gettime(CLOCK_REALTIME, &last);
		}
	}
	free(buf);
	fclose(fp);

	// Wait until all object-creation callbacks have occurred.
	dsos_obj_wait_for_all();

	if (progress && (num_objs % progress))
		print_elapsed(num_objs % progress, num_objs, beg, last);

	dsos_container_close(cont, SOS_COMMIT_SYNC);
	return 0;
}

/*
 * dsos_cmd iter --cont /tmp/cont.sos --schema test --attr seq
 */
int do_iter(int ac, char *av[])
{
	int		c, i, first, len;
	char		*attr_nm = NULL, *cont_nm = NULL, *schema_nm = NULL;
	sos_obj_t	obj;
	sos_attr_t	attr;
	dsos_t		*cont;
	sos_schema_t	schema;
	dsos_iter_t	*iter;

	struct option	lopts[] = {
		{ "attr",	required_argument, NULL, 'a' },
		{ "cont",	required_argument, NULL, 'c' },
		{ "schema",	required_argument, NULL, 's' },
		{ 0,		0,		   0,     0  }
	};

	while ((c = getopt_long_only(ac, av, "c:s:", lopts, NULL)) != -1) {
		switch (c) {
		    case 'a': attr_nm   = strdup(optarg); break;
		    case 'c': cont_nm   = strdup(optarg); break;
		    case 's': schema_nm = strdup(optarg); break;
		    default:
			usage();
			fprintf(stderr, "options:\n");
			fprintf(stderr, "  --attr <name>      Attribute name\n");
			fprintf(stderr, "  --cont <path>      Container path\n");
			fprintf(stderr, "  --schema <name>    Schema name\n");
			return 1;
		}
	}
	if (!attr_nm || !cont_nm || !schema_nm) {
		fprintf(stderr, "must specify --attr, --cont, and --schema\n");
		return 1;
	}

	cont = dsos_container_open(cont_nm, 0755);
	if (!cont) {
		dsos_perror("could not open container\n");
		return 1;
	}
	schema = dsos_schema_by_name(cont, schema_nm);
	if (!schema) {
		dsos_perror("could not open schema '%s'\n", schema_nm);
		return 1;
	}
	if (attr_nm[0] == '#')
		attr = sos_schema_attr_by_id(schema, atoi(attr_nm+1));
	else
		attr = sos_schema_attr_by_name(schema, attr_nm);
	if (!attr) {
		dsos_perror("could not find attribute '%s'\n", attr_nm);
		return 1;
	}
	iter = dsos_attr_iter_new(attr);
	if (!iter) {
		dsos_perror("could not create iter\n");
		return 1;
	}

	dsos_iter_begin(iter);
	while (obj = dsos_iter_obj(iter)) {
		dump_obj(obj);
		sos_obj_put(obj);
		dsos_iter_next(iter);
	}

	dsos_iter_free(iter);
	dsos_container_close(cont, SOS_COMMIT_SYNC);

	return 0;
}

/*
 * dsos_cmd delete --cont /tmp/cont.sos --schema test --attr seq --num 1000
 */
int do_delete(int ac, char *av[])
{
	int		c, i, first, len, num = -1;
	char		*attr_nm = NULL, *cont_nm = NULL, *schema_nm = NULL;
	sos_obj_t	obj;
	sos_attr_t	attr;
	dsos_t		*cont;
	sos_schema_t	schema;
	dsos_iter_t	*iter;

	struct option	lopts[] = {
		{ "attr",	required_argument, NULL, 'a' },
		{ "cont",	required_argument, NULL, 'c' },
		{ "schema",	required_argument, NULL, 's' },
		{ "num",	required_argument, NULL, 'n' },
		{ 0,		0,		   0,     0  }
	};

	while ((c = getopt_long_only(ac, av, "c:s:", lopts, NULL)) != -1) {
		switch (c) {
		    case 'a': attr_nm   = strdup(optarg); break;
		    case 'c': cont_nm   = strdup(optarg); break;
		    case 'n': num       = atoi(optarg); break;
		    case 's': schema_nm = strdup(optarg); break;
		    default:
			usage();
			fprintf(stderr, "options:\n");
			fprintf(stderr, "  --attr <name>      Attribute name\n");
			fprintf(stderr, "  --cont <path>      Container path\n");
			fprintf(stderr, "  --schema <name>    Schema name\n");
			fprintf(stderr, "  --num <numobjs>    Number of objects to delete (default is all)\n");
			return 1;
		}
	}
	if (!attr_nm || !cont_nm || !schema_nm) {
		fprintf(stderr, "must specify --attr, --cont, and --schema\n");
		return 1;
	}

	cont = dsos_container_open(cont_nm, 0755);
	if (!cont) {
		dsos_perror("could not open container\n");
		return 1;
	}
	schema = dsos_schema_by_name(cont, schema_nm);
	if (!schema) {
		dsos_perror("could not open schema '%s'\n", schema_nm);
		return 1;
	}
	if (attr_nm[0] == '#')
		attr = sos_schema_attr_by_id(schema, atoi(attr_nm+1));
	else
		attr = sos_schema_attr_by_name(schema, attr_nm);
	if (!attr) {
		dsos_perror("could not find attribute '%s'\n", attr_nm);
		return 1;
	}
	iter = dsos_attr_iter_new(attr);
	if (!iter) {
		dsos_perror("could not create iter\n");
		return 1;
	}

	for (i = 0; (i < num) && !dsos_iter_begin(iter); ++i) {
		obj = dsos_iter_obj(iter);
		dsos_obj_delete(obj);
		sos_obj_put(obj);
	}

	dsos_iter_free(iter);
	dsos_container_close(cont, SOS_COMMIT_SYNC);

	return 0;
}

/*
 * dsos_cmd find --cont=/tmp/cont.sos --schema=test <attr_name>=<value>
 */
int do_find(int ac, char *av[])
{
	int		c, i, ret;
	char		attr_nm[64], val_str[64];
	char		*cont_nm = NULL, *schema_nm = NULL;
	dsos_t		*cont;
	sos_schema_t	schema;
	dsos_iter_t	*iter;
	sos_attr_t	attr;
	sos_value_t	val;
	sos_key_t	key;
	sos_obj_t	obj;

	struct option	lopts[] = {
		{ "cont",	required_argument, NULL, 'c' },
		{ "schema",	required_argument, NULL, 's' },
		{ 0,		0,		   0,     0  }
	};

	while ((c = getopt_long_only(ac, av, "c:s:", lopts, NULL)) != -1) {
		switch (c) {
		    case 'c': cont_nm   = strdup(optarg); break;
		    case 's': schema_nm = strdup(optarg); break;
		    default:
			usage();
			fprintf(stderr, "options:\n");
			fprintf(stderr, "  --cont <path>      Container path\n");
			fprintf(stderr, "  --schema <name>    Schema name\n");
			return 1;
		}
	}
	if (!cont_nm || !schema_nm) {
		fprintf(stderr, "must specify --cont and --schema\n");
		return 1;
	}
	cont = dsos_container_open(cont_nm, 0755);
	if (!cont) {
		dsos_perror("could not open container\n");
		return 1;
	}
	schema = dsos_schema_by_name(cont, schema_nm);
	if (!schema) {
		dsos_perror("could not open schema '%s'\n", schema_nm);
		return 1;
	}
	if (optind >= ac) {
		fprintf(stderr, "must specify attr=value\n");
		return 1;
	}
	ret = sscanf(av[optind], "%64[^=]=%64s", attr_nm, val_str);
	if (ret != 2) {
		fprintf(stderr, "syntax error: must specify attr=value\n");
		return 1;
	}
	attr = sos_schema_attr_by_name(schema, attr_nm);
	if (!attr) {
		dsos_perror("could not find attribute '%s'\n", attr_nm);
		return 1;
	}

	val = sos_value_init(sos_value_new(), NULL, attr);
	ret = sos_value_from_str(val, val_str, NULL);
	if (ret) {
		fprintf(stderr, "invalid valid specified\n");
		return 1;
	}
	key = sos_key_new(sos_attr_key_size(attr));
	if (!key) {
		fprintf(stderr, "could not create new key\n");
		return 1;
	}
	sos_key_set(key, sos_value_as_key(val), sos_attr_key_size(attr));

	iter = dsos_attr_iter_new(attr);
	if (!iter) {
		dsos_perror("could not create iter\n");
		return 1;
	}

	if (dsos_iter_find(iter, key)) {
		printf("not found\n");
		ret = 1;
	} else {
		obj = dsos_iter_obj(iter);
		dump_obj(obj);
		sos_obj_put(obj);
		ret = 0;
	}

	sos_key_put(key);
	sos_value_put(val);
	sos_value_free(val);
	dsos_iter_free(iter);
	dsos_container_close(cont, SOS_COMMIT_SYNC);

	return ret;
}

/*
 * dsos_cmd ping --server 3 --numiters 10 --sleep 0.1
 * dsos_cmd ping --all
 */
int do_ping(int ac, char *av[])
{
	int			c, i, j, ret, dump = 0, num_iters = 1, server_num = -1;
	double			int_part, sleep_f = 1.0;
	struct timespec		beg, end, sleep_ts;
	struct dsos_ping_stats	stats, *statsp;

	struct option	lopts[] = {
		{ "all",	no_argument,       NULL, 'a' },
		{ "dump",	no_argument,       NULL, 'd' },
		{ "numiters",	required_argument, NULL, 'n' },
		{ "server",	required_argument, NULL, 's' },
		{ "sleep",	required_argument, NULL, 'l' },
		{ 0,		0,		   0,     0  }
	};

	while ((c = getopt_long_only(ac, av, "adl:n:s:", lopts, NULL)) != -1) {
		switch (c) {
		    case 'a': server_num = -1; break;
		    case 'd': dump = 1; break;
		    case 'l': sleep_f    = atof(optarg); break;
		    case 'n': num_iters  = atoi(optarg); break;
		    case 's': server_num = atoi(optarg); break;
		    default:
			usage();
			fprintf(stderr, "options:\n");
			fprintf(stderr, "  --all           Ping all servers\n");
			fprintf(stderr, "  --server <n>    Server to ping (0..N-1)\n");
			fprintf(stderr, "  --numiters <n>  Numbers of pings\n");
			fprintf(stderr, "  --sleep <secs>  Sleep time between pings\n");
			return 1;
		}
	}
	if ((server_num != -1) && ((server_num < 0) || (server_num > g.num_servers))) {
		fprintf(stderr, "invalid server number %d\n", server_num);
		return 1;
	}
	sleep_ts.tv_nsec = modf(sleep_f, &int_part) * 1.0e+9;
	sleep_ts.tv_sec  = (int)int_part;

	for (i = 0; i < num_iters; ++i) {
		if (server_num == -1) {
			ret = dsos_ping_all(&statsp, dump);
		} else {
			ret = dsos_ping_one(server_num, &stats, dump);
			statsp = &stats;
		}
		if (ret) {
			dsos_perror("ping error %d\n", ret);
			return 1;
		}
		for (j = 0; j < g.num_servers; ++j) {
			printf("server %d: %d/%d conn/disc %d reqs %d clients creates: %d/%d gets: %d/%d %f msec\n",
			       server_num == -1 ? j : server_num,
			       statsp[j].tot_num_connects,
			       statsp[j].tot_num_disconnects,
			       statsp[j].tot_num_reqs,
			       statsp[j].num_clients,
			       statsp[j].tot_num_obj_creates_inline,
			       statsp[j].tot_num_obj_creates_rma,
			       statsp[j].tot_num_obj_gets_inline,
			       statsp[j].tot_num_obj_gets_rma,
			       statsp[j].nsecs/1000000.0);
			if (server_num >= 0)
				break;
		}
		if (server_num == -1)
			free(statsp);
		if (i != (num_iters-1))
			nanosleep(&sleep_ts, NULL);
	}

	return 0;
}

/* For RBT that maps schema name -> DSOS schema. */
struct migrate_rbn {
	struct rbn	rbn;
	sos_schema_t	dsos_schema;
};

/* This is used as the context argument for migrate_cb. */
struct migrate_ctxt_s {
	int		num_objs;
	int		max_objs;
	int		verbose;
	int		progress;
	struct timespec	ts_beg;
	struct timespec	ts_last;
};

static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;

static int migrate_rbn_cmp_fn(void *tree_key, void *key)
{
	return strcmp(tree_key, key);
}

static void migrate_schema_add(const char *schema_nm, sos_schema_t dsos_schema)
{
	struct migrate_rbn *rbn = (struct migrate_rbn *)rbt_find(&migrate_rbt, (void *)schema_nm);
	if (!rbn) {
		rbn = calloc(1, sizeof(*rbn));
		if (!rbn) return;
		rbn->rbn.key     = strdup(schema_nm);
		rbn->dsos_schema = dsos_schema;
		rbt_ins(&migrate_rbt, (struct rbn *)rbn);
	} else {
		printf("schema %s already exists\n", schema_nm);
	}
}

static sos_schema_t migrate_schema_map(const char *schema_nm)
{
	struct migrate_rbn *rbn = (struct migrate_rbn *)rbt_find(&migrate_rbt, (void *)schema_nm);
	assert(rbn);
	return rbn->dsos_schema;
}

static void dsos_cb(sos_obj_t dsos_obj, void *ctxt)
{
	struct migrate_ctxt_s	*args = ctxt;

	if (args->verbose) {
		pthread_mutex_lock(&log_lock);
		printf("DSOS obj %p created %d:%d\n",
		       dsos_obj,
		       dsos_obj->obj_ref.ref.ods, dsos_obj->obj_ref.ref.obj);
		pthread_mutex_unlock(&log_lock);
	}

	sos_obj_put(dsos_obj);
}

static int migrate_cb(sos_part_t part, sos_obj_t sos_obj, void *ctxt)
{
	sos_obj_t		dsos_obj;
	sos_schema_t		sos_schema, dsos_schema;
	struct migrate_ctxt_s	*args = ctxt;

	sos_schema = sos_obj_schema(sos_obj);
	dsos_schema = migrate_schema_map(sos_schema_name(sos_schema));

	++args->num_objs;

	dsos_obj = dsos_obj_alloc(dsos_schema);
	if (!dsos_obj) {
		printf("out of memory\n");
		return 1;
	}

	if (args->verbose) {
		pthread_mutex_lock(&log_lock);
		printf("SOS obj %p %d:%d -> DSOS obj %p\n",
		       sos_obj,
		       sos_obj_ref(sos_obj).ref.ods,
		       sos_obj_ref(sos_obj).ref.obj,
		       dsos_obj);
		pthread_mutex_unlock(&log_lock);
	}
	if (args->progress && ((args->num_objs % args->progress) == 0)) {
		print_elapsed(args->progress, args->num_objs, args->ts_beg, args->ts_last);
		clock_gettime(CLOCK_REALTIME, &args->ts_last);
	}

	sos_obj_copy(dsos_obj, sos_obj);
	dsos_obj_create(dsos_obj, dsos_cb, ctxt);

	sos_obj_put(sos_obj);

	if (args->max_objs != -1)
		return (args->num_objs >= args->max_objs);
	return 0;  // keep going
}

/*
 * dsos_cmd migrate --sos-cont /tmp/cont.sos --dsos-cont /tmp/cont.dsos [--schema schema_to_copy]
 */
int do_migrate(int ac, char *av[])
{
	int		c, i, num_objs, ret;
	int		progress = 0, verbose = 0, max_objs = -1;
	char		*dsos_cont_nm = NULL, *sos_cont_nm = NULL, *schema_nm = NULL;
	dsos_t		*dsos_cont;
	dsos_part_t	*part;
	sos_t		sos_cont;
	sos_schema_t	sos_schema, dsos_schema;
	sos_obj_t	obj;
	sos_iter_t	sos_iter;
	sos_attr_t	attr;
	struct migrate_ctxt_s ctxt;

	struct option	lopts[] = {
		{ "dsos-cont",	required_argument, NULL, 'd' },
		{ "sos-cont",	required_argument, NULL, 'c' },
		{ "num",        required_argument, NULL, 'n' },
		{ "schema",	required_argument, NULL, 's' },
		{ "progress",   optional_argument, NULL, 'g' },
		{ "verbose",	no_argument,       NULL, 'v' },
		{ 0,		0,		   0,     0  }
	};

	while ((c = getopt_long_only(ac, av, "c:dg:s:v", lopts, NULL)) != -1) {
		switch (c) {
		    case 'c': sos_cont_nm  = strdup(optarg); break;
		    case 'd': dsos_cont_nm = strdup(optarg); break;
		    case 's': schema_nm    = strdup(optarg); break;
		    case 'n': max_objs     = atoi(optarg); break;
		    case 'v': verbose      = 1; break;
		    case 'g':
			if (optarg)
				progress = atoi(optarg);
			else
				progress = 10000;
			break;
		    default:
			usage();
			fprintf(stderr, "options:\n");
			fprintf(stderr, "  --sos-cont <path>    SOS container path to read\n");
			fprintf(stderr, "  --dsos-cont <path>   DSOS container path to create\n");
			fprintf(stderr, "  --schema <name>      optional: schema to migrate\n");
			fprintf(stderr, "  --num <max_objs>     optional: max # objects to migrate\n");
			fprintf(stderr, "  --progress [n]       optional: show rate every n objects\n");
			fprintf(stderr, "  --verbose\n");
			return 1;
		}
	}
	if (!sos_cont_nm || !dsos_cont_nm) {
		fprintf(stderr, "must specify --sos-cont and --dsos-cont\n");
		return 1;
	}

	rbt_init(&migrate_rbt, migrate_rbn_cmp_fn);

	/* SOS init */
	sos_cont = sos_container_open(sos_cont_nm, 0644);
	if (!sos_cont) {
		perror("could not open SOS container\n");
		return 1;
	}

	/* DSOS init */
	ret = dsos_container_new(dsos_cont_nm, 0755);
	if (ret) {
		dsos_perror("could not create container\n");
		exit(1);
	}
	dsos_cont = dsos_container_open(dsos_cont_nm, 0644);
	if (!dsos_cont) {
		dsos_perror("could not open container\n");
		exit(1);
	}
	ret = dsos_part_create(dsos_cont, "ROOT", NULL);
	if (ret) {
		dsos_perror("coult not create partition\n");
		exit(1);
	}
	part = dsos_part_find(dsos_cont, "ROOT");
	if (!part) {
		dsos_perror("coult not find partition\n");
		exit(1);
	}
	ret = dsos_part_state_set(part, SOS_PART_STATE_PRIMARY);
	if (ret) {
		dsos_perror("coult not set partition state\n");
		exit(1);
	}

	/*
	 * Iterate through schema in the SOS container and create
	 * the schema in DSOS, keeping a map from schema name to
	 * the DSOS sos_schema_t. This is needed in the migrate_cb
	 * iterator callback to get the DSOS schema which is needed
	 * to create the DSOS object. Note that we cannot simply
	 * use the SOS sos_schema_t because, although the two schema
	 * are identical, the DSOS sos_schemat contains DSOS-specific
	 * internal state needed to create a DSOS object.
	 */
	for (sos_schema = sos_schema_first(sos_cont);
	     sos_schema;
	     sos_schema = sos_schema_next(sos_schema)) {
		const char *sos_schema_nm = sos_schema_name(sos_schema);
		if (schema_nm && strcmp(sos_schema_nm, schema_nm))
			continue;
		ret = dsos_schema_add(dsos_cont, sos_schema);
		if (ret) {
			dsos_perror("error migrating schema %s to DSOS\n", schema_nm);
			return 1;
		}
		dsos_schema = dsos_schema_by_name(dsos_cont, schema_nm);
		assert(dsos_schema);
		migrate_schema_add(sos_schema_nm, dsos_schema);
		if (verbose)
			printf("migrated schema %s\n", sos_schema_nm);
	}

	if (verbose)
		printf("begin iteration\n");
	ctxt.num_objs = 0;
	ctxt.max_objs = max_objs;
	ctxt.verbose  = verbose;
	ctxt.progress = progress;
	clock_gettime(CLOCK_REALTIME, &ctxt.ts_beg);
	clock_gettime(CLOCK_REALTIME, &ctxt.ts_last);
	sos_part_obj_iter(__sos_primary_obj_part(sos_cont), NULL, migrate_cb, &ctxt);

	// Wait until all object-creation callbacks have occurred.
	if (verbose)
		printf("end iteration. waiting for all callbacks. %d objects.\n", ctxt.num_objs);
	dsos_obj_wait_for_all();
	if (progress && (ctxt.num_objs % progress)) {
		clock_gettime(CLOCK_REALTIME, &ctxt.ts_last);
		print_elapsed(ctxt.num_objs % progress, ctxt.num_objs, ctxt.ts_beg, ctxt.ts_last);
	}
	if (verbose)
		printf("all callbacks complete.\n");

	return 0;
}

double elapsed(struct timespec beg, struct timespec end)
{
	struct timespec	elapsed;

	if ((end.tv_nsec - beg.tv_nsec) < 0) {
		elapsed.tv_sec  = end.tv_sec - beg.tv_sec-1;
		elapsed.tv_nsec = 1000000000 + end.tv_nsec - beg.tv_nsec;
	} else {
		elapsed.tv_sec  = end.tv_sec  - beg.tv_sec;
		elapsed.tv_nsec = end.tv_nsec - beg.tv_nsec;
	}
	return elapsed.tv_sec + elapsed.tv_nsec/1.0e+9;
}

struct {
	char		*name;
	sos_type_t	type;
	int		array;
} type_names[] = {
	{ "int16",	SOS_TYPE_INT16,        0 },
	{ "int32",	SOS_TYPE_INT32,        0 },
	{ "int64",	SOS_TYPE_INT64,        0 },
	{ "uint16",	SOS_TYPE_UINT16,       0 },
	{ "uint32",	SOS_TYPE_UINT32,       0 },
	{ "uint64",	SOS_TYPE_UINT64,       0 },
	{ "float",	SOS_TYPE_FLOAT,        0 },
	{ "double",	SOS_TYPE_DOUBLE,       0 },
	{ "longdouble",	SOS_TYPE_LONG_DOUBLE,  0 },
	{ "timestamp",	SOS_TYPE_TIMESTAMP,    0 },
	{ "struct[",	SOS_TYPE_STRUCT,       1 },
	{ "byte[",	SOS_TYPE_BYTE_ARRAY,   1 },
	{ "char[",	SOS_TYPE_CHAR_ARRAY,   1 },
	{ "int16[",	SOS_TYPE_INT16_ARRAY,  1 },
	{ "int32[",	SOS_TYPE_INT32_ARRAY,  1 },
	{ "int64[",	SOS_TYPE_INT64_ARRAY,  1 },
	{ "uint16[",	SOS_TYPE_UINT16_ARRAY, 1 },
	{ "uint32[",	SOS_TYPE_UINT32_ARRAY, 1 },
	{ "uint64[",	SOS_TYPE_UINT64_ARRAY, 1 },
	{ "float[",	SOS_TYPE_FLOAT_ARRAY,  1 },
	{ "double[",	SOS_TYPE_DOUBLE_ARRAY, 1 },
	{ "longdouble[",SOS_TYPE_LONG_DOUBLE_ARRAY, 1 },
	{ NULL, 0, 0 }
};

void parse_attr_type(sos_schema_template_attr_t attr, char *s)
{
	int	i;

	for (i = 0; type_names[i].name; ++i) {
		if (!strncmp(type_names[i].name, s, strlen(type_names[i].name))) {
			attr->type = type_names[i].type;
			if (type_names[i].array) {
				attr->size = atoi(s + strlen(type_names[i].name));
			} else {
				attr->size = 0;
			}
			return;
		}
	}
}

/*
 * Parse a schema syntax like the following and return a newly allocated
 * sos_schema_template structure. Caller must free.
 *
 * [*]<attr_name>:<attr_type>[<attr_size>][,...]
 *
 * example:   *seq:uint64,data:char[9000]
 *
 * The '*' means the attribute is indexed.
 *
 * Note that this doesn't set the name in the returned schema template,
 * only the attributes.
 */
sos_schema_template_t parse_schema_template(const char *schema_nm, char *template)
{
	int			i, num_attrs;
	char			*t;
	sos_schema_template_t	ret;

	/* num_attrs is the number of commas + 1 */
	for (num_attrs = 1, t = template; *t; ++t) {
		if (*t == ',')
			++num_attrs;
	}

	ret = (sos_schema_template_t)calloc(1,
			sizeof(struct sos_schema_template) +
			sizeof(struct sos_schema_template_attr) * (num_attrs+1));
	if (!ret)
		return NULL;

	ret->name = schema_nm;

	i = 0;
	t = template;
	while (t) {
		ret->attrs[i].indexed  = 0;
		ret->attrs[i].idx_type = NULL;
		ret->attrs[i].key_type = NULL;
		ret->attrs[i].idx_args = NULL;
		if (*t == '*') {
			ret->attrs[i].indexed = 1;
			++t;
		}
		ret->attrs[i].name = t;
		t = strchr(t, ':');
		if (!t) {
			fprintf(stderr, "missing : in schema template\n");
			return NULL;
		}
		*t++ = 0;
		parse_attr_type(&ret->attrs[i], t);
		t = strchr(t, ',');
		if (t) {
			*t++ = 0;
		} else {
			break;
		}
		++i;
	}
	return ret;
}

void dump_schema(sos_schema_t sos_schema)
{
	int		i, first = 1;
	sos_attr_t	attr;

	TAILQ_FOREACH(attr, &sos_schema->attr_list, entry) {
		if (!first)
			printf(",");
		first = 0;
		for (i = 0; type_names[i].name; ++i) {
			if (type_names[i].type == attr->data->type)
				break;
		}
		if (!type_names[i].name)
			continue;
		if (type_names[i].array) {
			printf("%s%s:%s%d]",
			       attr->data->indexed ? "*" : "",
			       attr->data->name,
			       type_names[i].name,
			       attr->data->count);
		} else {
			printf("%s%s:%s",
			       attr->data->indexed ? "*" : "",
			       attr->data->name,
			       type_names[i].name);
		}
	}
	printf("\n");
}

void dump_obj(sos_obj_t sos_obj)
{
	int		bufsz, i, len, first = 1;
	char		*buf;
	sos_schema_t	sos_schema;
	sos_attr_t	attr;

	bufsz = 80;
	buf   = malloc(bufsz);

	for (i = 0; i < sos_schema_attr_count(sos_obj->schema); ++i) {
		if (!first)
			printf(",");
		first = 0;
		attr = sos_schema_attr_by_id(sos_obj->schema, i);
		len  = sos_obj_attr_strlen(sos_obj, attr);
		if (len > bufsz) {
			free(buf);
			bufsz = len;
			buf   = malloc(bufsz);
		}
		printf("%s", sos_obj_attr_to_str(sos_obj, attr, buf, bufsz));
	}
	printf("\n");

	free(buf);
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

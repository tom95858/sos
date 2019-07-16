#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>
#include <getopt.h>
#include "dsos_priv.h"

/*
 * The DSOS client establishes connections to the N DSOS servers.  The
 * json config file contains the DSOS ring parameters. When the user
 * calls into DSOS, a request message is generated and sent to the
 * appropriate server. Each request message has a unique 64-bit id
 * that is reflected back by the server in its response message. This
 * id is used to map the response back to the original request.
 */

/* Global variables. */
struct globals_s	g;
__thread dsos_err_t	dsos_errno;

#define ROUNDUP(s,r)	((s + (r - 1)) & ~(r - 1))

static void *shared_heap_alloc(size_t sz)
{
	return mm_alloc(g.heap, sz);
}

static void shared_heap_free(void *p)
{
	mm_free(g.heap, p);
}

void dsos_log(const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	fflush(stdout);
}

int dsos_init(const char *config_filename)
{
	int		i, ret;
	zap_err_t	zerr;
	dsos_conn_t	*conn;
	zap_map_t	map;

	/* Read json config file. */
	ret = dsos_config_read(config_filename);
	if (ret)
		return ENOENT;

	dsos_errno = dsos_err_new();

	g.zap = zap_get(g.opts.zap_prov_name, dsos_log, NULL);
	if (!g.zap) {
		dsos_err_set_local_all(dsos_errno, ENETDOWN);
		return DSOS_ERR_LOCAL;
	}

	dsos_err_clear(dsos_errno);
	for (i = 0; i < g.num_servers; ++i) {
		ret = dsos_connect(g.conns[i].host, g.conns[i].service, g.conns[i].server_id, 0);
		if (ret) {
			dsos_err_set_local(dsos_errno, i, ret);
			dsos_error("err %d (%s) connecting to server %d at %s:%s\n",
				   ret, zap_err_str(ret), i, g.conns[i].host, g.conns[i].service);
		}
	}
	if (dsos_err_status(dsos_errno) & DSOS_ERR_LOCAL)
		return DSOS_ERR_LOCAL;
	for (i = 0; i < g.num_servers; ++i) {
		sem_wait(&g.conns[i].conn_sem);
		dsos_err_set_local(dsos_errno, i, g.conns[i].conn_status);
	}
	if (ret = dsos_err_status(dsos_errno))
		return ret;
	dsos_debug("connected to %d servers\n", g.num_servers);

	/*
	 * Create a heap and zap_share it with all servers.
	 */

	if (!g.opts.heap_sz)
		g.opts.heap_sz = DSOS_DEFAULT_SHARED_HEAP_SZ;
	g.opts.heap_sz = ROUNDUP(g.opts.heap_sz, 4096);

	if (!g.opts.heap_grain_sz)
		g.opts.heap_grain_sz = DSOS_DEFAULT_SHARED_HEAP_GRAIN_SZ;

	g.heap_buf = malloc(g.opts.heap_sz);
	if (!g.heap_buf)
		dsos_fatal("out of memory\n");

	g.heap = mm_new(g.heap_buf, g.opts.heap_sz, g.opts.heap_grain_sz);
	if (!g.heap)
		dsos_fatal("could not create shared heap\n");

	ods_obj_allocator_set(shared_heap_alloc, shared_heap_free);

	dsos_err_clear(dsos_errno);
	for (i = 0; i < g.num_servers; ++i) {
		conn = &g.conns[i];
		zerr = zap_map(conn->ep, &conn->map, g.heap_buf, g.opts.heap_sz, ZAP_ACCESS_READ);
		if (zerr) {
			dsos_error("srv %d: err %d (%s) mapping shared heap %p sz %d\n",
				   i, zerr, zap_err_str(zerr), g.heap_buf, g.opts.heap_sz);
			dsos_err_set_local(dsos_errno, i, zerr);
			continue;
		}
		zerr = zap_share(conn->ep, conn->map, NULL, 0);
		if (zerr) {
			dsos_error("srv %d: err %d (%s) sharing heap map %p\n", i, conn->map);
			dsos_err_set_local(dsos_errno, i, zerr);
			continue;
		}
		dsos_debug("heap %p/%d has map %p for server %d\n",
			   g.heap_buf, g.opts.heap_sz, conn->map, i);
	}
	if (ret = dsos_err_status(dsos_errno))
		return ret;

	dsos_rpc_init();

	return 0;
}

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

#define ROUNDUP(s,r)	((s + (r - 1)) & ~(r - 1))

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

	g.zap = zap_get(g.opts.zap_prov_name, dsos_log, NULL);
	if (!g.zap)
		return ENETDOWN;

	dsos_err_clear();
	for (i = 0; i < g.num_servers; ++i) {
		ret = dsos_connect(g.conns[i].host, g.conns[i].service, g.conns[i].server_id);
		dsos_err_set(i, ret);
#if 0
		if (ret)
			dsos_fatal("err %d (%s) connecting to server %d at %s:%s\n",
				   ret, zap_err_str(ret), i, g.conns[i].host, g.conns[i].service);
#endif
	}
	if (dsos_err_status())
		return ECONNREFUSED;
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
		return;

	dsos_err_clear();
	for (i = 0; i < g.num_servers; ++i) {
		conn = &g.conns[i];
		zerr = zap_map(conn->ep, &conn->map, g.heap_buf, g.opts.heap_sz, ZAP_ACCESS_READ);
		zerr = zerr || zap_share(conn->ep, conn->map, NULL, 0);
		dsos_err_set(i, ret);
#if 0
		if (zerr)
			dsos_error("zap_map/zap_share err %d %s\n", zerr, zap_err_str(zerr));
#endif
	}
	if (dsos_err_status())
		return EREMOTE;

	dsos_req_init();

	return 0;
}

void dsos_disconnect(void)
{
	int	i, ret;

	dsos_debug("starting\n");
	for (i = 0; i < g.num_servers; ++i) {
		ret = zap_close(g.conns[i].ep);
		if (ret)
			dsos_error("disconnect err %d\n", ret);
		zap_free(g.conns[i].ep);
	}
	dsos_debug("done\n");
}

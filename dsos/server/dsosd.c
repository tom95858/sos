#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <assert.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netdb.h>
#include "dsosd_priv.h"
#include "dsosd_msg_layout.h"

struct globals_s	g;

static void	dsosd_log(const char *fmt, ...);
static void	handle_connect_err(zap_ep_t ep);
static void	handle_connect_req(zap_ep_t ep);
static void	handle_connected(zap_ep_t ep);
static void	handle_disconnected(zap_ep_t ep);
static void	handle_msg(zap_ep_t ep, dsosd_msg_t *msg, size_t len);
static void	handle_read_complete(zap_ep_t ep, void *ctxt);
static void	handle_rejected(zap_ep_t ep);
static void	handle_rendezvous(zap_ep_t ep, zap_map_t map, void *buf, size_t len);
static void	handle_write_complete(zap_ep_t ep, void *ctxt);
static void	server_cb(zap_ep_t ep, zap_event_t ev);

static void usage(char *av[])
{
	fprintf(stderr, "usage: %s [options]\n", av[0]);
	fprintf(stderr, "options:\n");
	fprintf(stderr, "  --daemon          Run in the background.\n");
	fprintf(stderr, "  --port <port>     Port or service name to listen on (required).\n");
	fprintf(stderr, "  --provider <name> Zap provider to use (required).\n");
	fprintf(stderr, "  --server <num>    This server's # within the DSOS (required).\n");
	fprintf(stderr, "  --srcaddr <addr>  Server listening interface (required).\n");
	fprintf(stderr, "  --help            Display this message.\n");
}

int main(int ac, char *av[])
{
	int			c, i, ret;
	dsosd_client_t		*client;
	struct sockaddr_in	sin;
	struct addrinfo		*ai;
	zap_err_t		zerr;

	struct option	lopts[] = {
		{ "daemon",	no_argument,       NULL, 'd' },
		{ "help",	no_argument,       NULL, 'h' },
		{ "port",	required_argument, NULL, 'p' },
		{ "provider",	required_argument, NULL, 'P' },
		{ "server",	required_argument, NULL, 'n' },
		{ "srcaddr",	required_argument, NULL, 's' },
		{ 0,		0,		   0,     0  }
	};

	memset(&g.opts, 0, sizeof(g.opts));
	g.opts.server_num = -1;
	while ((c = getopt_long_only(ac, av, "", lopts, NULL)) != -1) {
		switch (c) {
		    case 'd':
			g.opts.daemon = 1;
			break;
		    case 'n':
			g.opts.server_num = atoi(optarg);
			break;
		    case 'p':
			g.opts.src_port = strdup(optarg);
			break;
		    case 'P':
			g.opts.zap_prov_name = strdup(optarg);
			break;
		    case 's':
			g.opts.src_addr = strdup(optarg);
			break;
		    default:
			usage(av);
			exit(0);
		}
	}

	if ((g.opts.server_num == -1) || !g.opts.src_port || !g.opts.zap_prov_name || !g.opts.src_addr)
		dsosd_fatal("required option missing\n");

	if (g.opts.daemon) {
		ret = daemon(1, 1);
		if (ret)
			dsosd_fatal("could not fork");
	}

	ret = getaddrinfo(g.opts.src_addr, g.opts.src_port, NULL, &ai);
	if (ret)
		dsosd_fatal("getaddrinfo error %d %s\n", ret, gai_strerror(ret));
	sin = *(struct sockaddr_in *)ai[0].ai_addr;
	freeaddrinfo(ai);

	g.zap = zap_get(g.opts.zap_prov_name, dsosd_log, NULL);
	if (!g.zap)
		dsosd_fatal("could not load transport\n");

	g.ep = zap_new(g.zap, server_cb);
	if (!g.ep)
		dsosd_fatal("could not create passive zap endpoint: %d\n", errno);

	sem_init(&g.exit_sem, 0, 0);

	zerr = zap_listen(g.ep, (struct sockaddr *)&sin, sizeof(sin));
	if (zerr)
		dsosd_fatal("zap_listen error: %d\n", zerr);

	sem_wait(&g.exit_sem);
	zap_close(g.ep);
	zap_free(g.ep);
	/* XXX Zap has issues on exit even with a sleep here. */
	sleep(2);
	return 0;
}

static void server_cb(zap_ep_t ep, zap_event_t ev)
{
	switch (ev->type) {
	    case ZAP_EVENT_CONNECT_REQUEST:
		handle_connect_req(ep);
		break;
	    case ZAP_EVENT_CONNECTED:
		handle_connected(ep);
		break;
	    case ZAP_EVENT_DISCONNECTED:
		handle_disconnected(ep);
		break;
	    case ZAP_EVENT_REJECTED:
		handle_rejected(ep);
		break;
	    case ZAP_EVENT_CONNECT_ERROR:
		handle_connect_err(ep);
		break;
	    case ZAP_EVENT_RECV_COMPLETE:
		handle_msg(ep, (dsosd_msg_t *)ev->data, ev->data_len);
		break;
	    case ZAP_EVENT_READ_COMPLETE:
		handle_read_complete(ep, ev->context);
		break;
	    case ZAP_EVENT_WRITE_COMPLETE:
		handle_write_complete(ep, ev->context);
		break;
	    case ZAP_EVENT_RENDEZVOUS:
		handle_rendezvous(ep, ev->map, ev->data, ev->data_len);
		break;
	    default:
		dsosd_error("unhandled Zap event %s\n", zap_event_str(ev->type));
		break;
	}
}

static void handle_connect_req(zap_ep_t ep)
{
	dsosd_client_t	*client;

	client = dsosd_client_new(ep);
	zap_accept(ep, server_cb, NULL, 0);
	zap_set_ucontext(ep, client);

#if 1
	// XXX map a heap we can RMA in to. This is temporary, until
	// SOS can take a heap allocator or can alloc from reg mem.
	client->heap_sz  = 4 * 1024 * 1024;
	client->heap_buf = malloc(client->heap_sz);
	zap_err_t zerr = zap_map(ep, &client->lmap, client->heap_buf, client->heap_sz, ZAP_ACCESS_NONE);
	if (zerr)
		dsosd_fatal("zap_map err %d %s\n", zerr, zap_err_str(zerr));
	client->heap = mm_new(client->heap_buf, client->heap_sz, 64);
	if (!client->heap)
		dsosd_fatal("could not create shared heap\n");
#endif
}

static void handle_connected(zap_ep_t ep)
{
	++g.stats.tot_num_connects;
	++g.num_clients;

#ifdef DSOSD_DEBUG
	struct sockaddr_in	lsin = {0};
	struct sockaddr_in	rsin = {0};
	socklen_t		slen;
	char			mybuf[16];

	slen = sizeof(lsin);
	zap_get_name(ep, (void *)&lsin, (void *)&rsin, &slen);
	inet_ntop(rsin.sin_family, &rsin.sin_addr, mybuf, sizeof(mybuf));
	dsosd_debug("connect %s:%d\n", mybuf, ntohs(rsin.sin_port));
#endif
}

static void handle_disconnected(zap_ep_t ep)
{
	dsosd_client_t	*client = (dsosd_client_t *)zap_get_ucontext(ep);

#ifdef DSOSD_DEBUG
	struct sockaddr_in	lsin = {0};
	struct sockaddr_in	rsin = {0};
	socklen_t		slen;
	char			mybuf[16];

	slen = sizeof(lsin);
	zap_get_name(ep, (void *)&lsin, (void *)&rsin, &slen);
	inet_ntop(rsin.sin_family, &rsin.sin_addr, mybuf, sizeof(mybuf));
	dsosd_debug("disconnect %s:%d\n", mybuf, ntohs(rsin.sin_port));
#endif
#if 1
	// XXX
	if (client->lmap)
		zap_unmap(ep, client->lmap);
	if (client->heap_buf)
		free(client->heap_buf);
#endif
	zap_free(ep);
	dsosd_client_put(client);
	--g.num_clients;
	++g.stats.tot_num_disconnects;
}

static void handle_rejected(zap_ep_t ep)
{
	dsosd_error("connect error ep %p\n", ep);
}

static void handle_connect_err(zap_ep_t ep)
{
	dsosd_error("connect error ep %p\n", ep);
}

static void handle_rendezvous(zap_ep_t ep, zap_map_t map, void *buf, size_t len)
{
	dsosd_client_t	*client = (dsosd_client_t *)zap_get_ucontext(ep);

	client->rmap = map;
	dsosd_debug("ep %p got map %p\n", ep, map);
}

// we get here as part of a DSOSD_OBJ_CREATE req
// the rma from the client is complete, finish the req
static void handle_read_complete(zap_ep_t ep, void *ctxt)
{
	int		ret;
	char		*obj_data;
	size_t		obj_max_sz;
	dsosd_req_t	*req = (dsosd_req_t *)ctxt;
	sos_obj_t	obj  = (sos_obj_t)req->ctxt;
	dsosd_client_t	*client = (dsosd_client_t *)zap_get_ucontext(ep);

#if 1
	/*
	 * Until SOS can map the mmap backing objects, copy the object
	 * from a temp buffer to the real object store. We'll RMA-read
	 * directly into the object once SOS is capable of mapping it.
	 */
	sos_obj_data_get(obj, &obj_data, &obj_max_sz);
	memcpy(obj_data, req->rma_buf, req->resp->u.obj_create_resp.len);
	mm_free(client->heap, req->rma_buf);
	req->rma_buf = NULL;
	*(uint64_t *)obj_data = sos_schema_id(obj->schema);
#endif
	ret = sos_obj_index(obj);
	if (ret)
		dsosd_error("ep %p sos_obj_index ret %d\n", ret);
	sos_obj_put(obj);

	req->resp->u.hdr.status = ret;
	req->resp->u.hdr.flags  = 0;
	dsosd_debug("new obj %p rma complete ret %d\n", obj, ret);
	dsosd_req_complete(req, sizeof(dsosd_msg_obj_create_resp_t));
}

static void handle_write_complete(zap_ep_t ep, void *ctxt)
{
}

static void handle_msg(zap_ep_t ep, dsosd_msg_t *msg, size_t len)
{
	++g.stats.tot_num_reqs;

	dsosd_debug("ep %p msg %p type %d id %ld len %d\n",
		    ep, msg, msg->u.hdr.type, msg->u.hdr.id, len);

	switch (msg->u.hdr.type) {
	    case DSOSD_MSG_PING_REQ:
		rpc_handle_ping(ep, (dsosd_msg_ping_req_t *)msg, len);
		break;
	    case DSOSD_MSG_OBJ_CREATE_REQ:
		rpc_handle_obj_create(ep, (dsosd_msg_obj_create_req_t *)msg, len);
		break;
	    case DSOSD_MSG_CONTAINER_NEW_REQ:
		rpc_handle_container_new(ep, (dsosd_msg_container_new_req_t *)msg, len);
		break;
	    case DSOSD_MSG_CONTAINER_OPEN_REQ:
		rpc_handle_container_open(ep, (dsosd_msg_container_open_req_t *)msg, len);
		break;
	    case DSOSD_MSG_CONTAINER_CLOSE_REQ:
		rpc_handle_container_close(ep, (dsosd_msg_container_close_req_t *)msg, len);
		break;
	    case DSOSD_MSG_PART_CREATE_REQ:
		rpc_handle_part_create(ep, (dsosd_msg_part_create_req_t *)msg, len);
		break;
	    case DSOSD_MSG_PART_FIND_REQ:
		rpc_handle_part_find(ep, (dsosd_msg_part_find_req_t *)msg, len);
		break;
	    case DSOSD_MSG_PART_SET_STATE_REQ:
		rpc_handle_part_set_state(ep, (dsosd_msg_part_set_state_req_t *)msg, len);
		break;
	    case DSOSD_MSG_SCHEMA_FROM_TEMPLATE_REQ:
		rpc_handle_schema_from_template(ep, (dsosd_msg_schema_from_template_req_t *)msg, len);
		break;
	    case DSOSD_MSG_SCHEMA_ADD_REQ:
		rpc_handle_schema_add(ep, (dsosd_msg_schema_add_req_t *)msg, len);
		break;
	    case DSOSD_MSG_SCHEMA_BY_NAME_REQ:
		rpc_handle_schema_by_name(ep, (dsosd_msg_schema_by_name_req_t *)msg, len);
		break;
	    default:
		dsosd_error("unhandled client req %d ep %p\n", msg->u.hdr.type, ep);
		break;
	}
}

static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;

static void dsosd_log(const char *fmt, ...)
{
	va_list	ap;

	pthread_mutex_lock(&log_lock);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	pthread_mutex_unlock(&log_lock);
}

dsosd_client_t *dsosd_client_new(zap_ep_t ep)
{
	dsosd_client_t	*client;

	client = (dsosd_client_t *)calloc(1, sizeof(dsosd_client_t));
	if (!client)
		dsosd_fatal("out of memory");

	client->refcount = 1;  // start with a reference
	client->ep       = ep;

	dsosd_debug("%p\n", client);
	return client;
}

void dsosd_client_get(dsosd_client_t *client)
{
	ods_atomic_inc(&client->refcount);
	dsosd_debug("%p refcount now %d\n", client, client->refcount);
}

void dsosd_client_put(dsosd_client_t *client)
{
	dsosd_debug("%p refcount was %d\n", client, client->refcount);
	if (!ods_atomic_dec(&client->refcount))
		free(client);
}

dsosd_req_t *dsosd_req_new(dsosd_client_t *client, uint16_t type, uint64_t msg_id, size_t max_msg_len)
{
	dsosd_req_t	*req;

	req = malloc(sizeof(dsosd_req_t));
	if (!req)
		dsosd_fatal("out of memory");

	req->refcount = 1;  // start with a reference
	req->client   = client;
	req->resp     = malloc(max_msg_len);
	if (!req->resp)
		dsosd_fatal("out of memory\n");
	req->resp_max_len       = max_msg_len;
	req->resp->u.hdr.type   = type;
	req->resp->u.hdr.id     = msg_id;
	req->resp->u.hdr.status = 0;
	req->resp->u.hdr.flags  = 0;

	dsosd_client_get(client);

	dsosd_debug("%p client %p type %d\n", req, client, type);

	return req;
}

zap_err_t dsosd_req_complete(dsosd_req_t *req, size_t len)
{
	zap_err_t	zerr;

	zerr = zap_send(req->client->ep, req->resp, len);
	if (zerr)
		dsosd_error("zap_send ep %p zerr %d %s\n", req->client->ep, zerr, zap_err_str(zerr));
	dsosd_req_put(req);
	return zerr;
}

void dsosd_req_get(dsosd_req_t *req)
{
	ods_atomic_inc(&req->refcount);
}

void dsosd_req_put(dsosd_req_t *req)
{
	dsosd_debug("%p\n", req);
	if (!ods_atomic_dec(&req->refcount)) {
		dsosd_client_put(req->client);
		free(req->resp);
		free(req);
	}
}

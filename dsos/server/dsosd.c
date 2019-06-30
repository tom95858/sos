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
	sleep(1);
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

	dsosd_debug("ep %p\n", ep);
	client = dsosd_client_new(ep);
	if (!client)
		goto err;
	zap_set_ucontext(ep, client);
	zap_accept(ep, server_cb, NULL, 0);
#if 1
	/*
	 * XXX Until SOS can provide for RMA directly to or from a
	 * container-backed object.
	 */
	zap_err_t zerr = zap_map(ep, &client->lmap, client->heap_buf, client->heap_sz, ZAP_ACCESS_NONE);
	if (zerr) {
		dsosd_error("zap_map err %d %s\n", zerr, zap_err_str(zerr));
		goto err;
	}
	client->heap = mm_new(client->heap_buf, client->heap_sz, 64);
	if (!client->heap) {
		dsosd_error("could not create shared heap\n");
		goto err;
	}
#endif
	return;
err:
	dsosd_error("closing ep %p for no resources\n", ep);
	zap_close(ep);
}

static void handle_connected(zap_ep_t ep)
{
	dsosd_client_t	*client = (dsosd_client_t *)zap_get_ucontext(ep);

	sem_post(&client->initialized_sem);

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
	dsosd_debug("connect %s:%d ep %p client %p\n",
		    mybuf, ntohs(rsin.sin_port), ep, client);
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
	dsosd_debug("disconnect %s:%d ep %p client %p\n",
		    mybuf, ntohs(rsin.sin_port), ep, client);
#endif
	dsosd_client_put(client);
	zap_free(ep);
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

// we get here as part of a create-object req
// the rma-read from the client is complete, finish the req
static void handle_read_complete(zap_ep_t ep, void *ctxt)
{
	int		ret;
	char		*obj_data;
	size_t		obj_max_sz;
	dsosd_req_t	*req = (dsosd_req_t *)ctxt;
	sos_obj_t	obj  = (sos_obj_t)req->ctxt;
	dsosd_client_t	*client = (dsosd_client_t *)zap_get_ucontext(ep);

#if 1
	/* Remove this once SOS can map objects directly. */
	sos_obj_data_get(obj, &obj_data, &obj_max_sz);
	assert(obj_max_sz == req->resp->u.hdr2.obj_sz);
	memcpy(obj_data, req->rma_buf, req->resp->u.hdr2.obj_sz);
	mm_free(client->heap, req->rma_buf);
#endif
	req->rma_buf = NULL;
	*(uint64_t *)obj_data = sos_schema_id(obj->schema);
	ret = sos_obj_index(obj);
	if (ret)
		dsosd_error("ep %p sos_obj_index ret %d\n", ret);
	sos_obj_put(obj);

	req->resp->u.hdr.status = ret;
	req->resp->u.hdr.flags  = 0;
	dsosd_debug("new obj %p rma-read complete ret %d\n", obj, ret);
	dsosd_req_complete(req, sizeof(dsosd_msg_obj_create_resp_t));
}

// we get here as part of an RMA-write of a SOS obj to the client
// the rma-write to the client is complete, finish the req
static void handle_write_complete(zap_ep_t ep, void *ctxt)
{
	dsosd_req_t	*req    = (dsosd_req_t *)ctxt;
	sos_obj_t	sos_obj = (sos_obj_t)req->ctxt;
	dsosd_client_t	*client = (dsosd_client_t *)zap_get_ucontext(ep);

#if 1
	/* Remove this once SOS can map objects directly. */
	mm_free(client->heap, req->rma_buf);
	req->rma_buf = NULL;
#endif
	sos_obj_put(sos_obj);

	req->resp->u.hdr.status = 0;
	req->resp->u.hdr.flags  = 0;
	dsosd_debug("obj %p rma-write complete\n", sos_obj);
	dsosd_req_complete(req, req->resp_len);
}

static const char *msg_type_to_str(int type)
{
	switch (type) {
	    case DSOSD_MSG_PING_REQ:
		return "DSOSD_MSG_PING_REQ";
	    case DSOSD_MSG_PING_RESP:
		return "DSOSD_MSG_PING_RESP";
	    case DSOSD_MSG_CONTAINER_NEW_REQ:
		return "DSOSD_CONTAINER_NEW_REQ";
	    case DSOSD_MSG_CONTAINER_NEW_RESP:
		return "DSOSD_CONTAINER_NEW_RESP";
	    case DSOSD_MSG_CONTAINER_OPEN_REQ:
		return "DSOSD_CONTAINER_OPEN_REQ";
	    case DSOSD_MSG_CONTAINER_OPEN_RESP:
		return "DSOSD_CONTAINER_OPEN_RESP";
	    case DSOSD_MSG_CONTAINER_DELETE_REQ:
		return "DSOSD_CONTAINER_DELETE_REQ";
	    case DSOSD_MSG_CONTAINER_DELETE_RESP:
		return "DSOSD_CONTAINER_DELETE_RESP";
	    case DSOSD_MSG_CONTAINER_CLOSE_REQ:
		return "DSOSD_CONTAINER_CLOSE_REQ";
	    case DSOSD_MSG_CONTAINER_CLOSE_RESP:
		return "DSOSD_CONTAINER_CLOSE_RESP";
	    case DSOSD_MSG_ITERATOR_CLOSE_REQ:
		return "DSOSD_ITERATOR_CLOSE_REQ";
	    case DSOSD_MSG_ITERATOR_CLOSE_RESP:
		return "DSOSD_ITERATOR_CLOSE_RESP";
	    case DSOSD_MSG_ITERATOR_NEW_REQ:
		return "DSOSD_ITERATOR_NEW_REQ";
	    case DSOSD_MSG_ITERATOR_NEW_RESP:
		return "DSOSD_ITERATOR_NEW_RESP";
	    case DSOSD_MSG_ITERATOR_STEP_REQ:
		return "DSOSD_ITERATOR_STEP_REQ";
	    case DSOSD_MSG_ITERATOR_STEP_RESP:
		return "DSOSD_ITERATOR_STEP_RESP";
	    case DSOSD_MSG_OBJ_CREATE_REQ:
		return "DSOSD_OBJ_CREATE_REQ";
	    case DSOSD_MSG_OBJ_CREATE_RESP:
		return "DSOSD_OBJ_CREATE_RESP";
	    case DSOSD_MSG_OBJ_GET_REQ:
		return "DSOSD_OBJ_GET_REQ";
	    case DSOSD_MSG_OBJ_GET_RESP:
		return "DSOSD_OBJ_GET_RESP";
	    case DSOSD_MSG_OBJ_DELETE_REQ:
		return "DSOSD_OBJ_DELETE_REQ";
	    case DSOSD_MSG_OBJ_DELETE_RESP:
		return "DSOSD_OBJ_DELETE_RESP";
	    case DSOSD_MSG_PART_CREATE_REQ:
		return "DSOSD_PART_CREATE_REQ";
	    case DSOSD_MSG_PART_CREATE_RESP:
		return "DSOSD_PART_CREATE_RESP";
	    case DSOSD_MSG_PART_FIND_REQ:
		return "DSOSD_PART_FIND_REQ";
	    case DSOSD_MSG_PART_FIND_RESP:
		return "DSOSD_PART_FIND_RESP";
	    case DSOSD_MSG_PART_SET_STATE_REQ:
		return "DSOSD_PART_SET_STATE_REQ";
	    case DSOSD_MSG_PART_SET_STATE_RESP:
		return "DSOSD_PART_SET_STATE_RESP";
	    case DSOSD_MSG_SCHEMA_FROM_TEMPLATE_REQ:
		return "DSOSD_SCHEMA_FROM_TEMPLATE_REQ";
	    case DSOSD_MSG_SCHEMA_FROM_TEMPLATE_RESP:
		return "DSOSD_SCHEMA_FROM_TEMPLATE_RESP";
	    case DSOSD_MSG_SCHEMA_ADD_REQ:
		return "DSOSD_SCHEMA_ADD_REQ";
	    case DSOSD_MSG_SCHEMA_ADD_RESP:
		return "DSOSD_SCHEMA_ADD_RESP";
	    case DSOSD_MSG_SCHEMA_BY_NAME_REQ:
		return "DSOSD_SCHEMA_BY_NAME_REQ";
	    case DSOSD_MSG_SCHEMA_BY_NAME_RESP:
		return "DSOSD_SCHEMA_BY_NAME_RESP";
	    default:
		return "<invalid>";
	}
}

static void handle_msg(zap_ep_t ep, dsosd_msg_t *msg, size_t len)
{
	dsosd_client_t	*client = (dsosd_client_t *)zap_get_ucontext(ep);

	assert(client->debug != 0xbadb0bad);

	if (!client->initialized) {
		dsosd_debug("ep %p client %p waiting for init\n", ep, client);
		sem_wait(&client->initialized_sem);
		client->initialized = 1;
	}

	++g.stats.tot_num_reqs;

	dsosd_debug("ep %p %s msg %p type %d id %ld len %d\n",
		    ep, msg_type_to_str(msg->u.hdr.type), msg,
		    msg->u.hdr.type, msg->u.hdr.id, len);

	switch (msg->u.hdr.type) {
	    case DSOSD_MSG_PING_REQ:
		rpc_handle_ping(ep, (dsosd_msg_ping_req_t *)msg, len);
		break;
	    case DSOSD_MSG_CONTAINER_NEW_REQ:
		rpc_handle_container_new(ep, (dsosd_msg_container_new_req_t *)msg, len);
		break;
	    case DSOSD_MSG_CONTAINER_OPEN_REQ:
		rpc_handle_container_open(ep, (dsosd_msg_container_open_req_t *)msg, len);
		break;
	    case DSOSD_MSG_CONTAINER_DELETE_REQ:
		rpc_handle_container_delete(ep, (dsosd_msg_container_delete_req_t *)msg, len);
		break;
	    case DSOSD_MSG_CONTAINER_CLOSE_REQ:
		rpc_handle_container_close(ep, (dsosd_msg_container_close_req_t *)msg, len);
		break;
	    case DSOSD_MSG_ITERATOR_CLOSE_REQ:
		rpc_handle_iterator_close(ep, (dsosd_msg_iterator_close_req_t *)msg, len);
		break;
	    case DSOSD_MSG_ITERATOR_NEW_REQ:
		rpc_handle_iterator_new(ep, (dsosd_msg_iterator_new_req_t *)msg, len);
		break;
	    case DSOSD_MSG_ITERATOR_STEP_REQ:
		rpc_handle_iterator_step(ep, (dsosd_msg_iterator_step_req_t *)msg, len);
		break;
	    case DSOSD_MSG_OBJ_CREATE_REQ:
		rpc_handle_obj_create(ep, (dsosd_msg_obj_create_req_t *)msg, len);
		break;
	    case DSOSD_MSG_OBJ_DELETE_REQ:
		rpc_handle_obj_delete(ep, (dsosd_msg_obj_delete_req_t *)msg, len);
		break;
	    case DSOSD_MSG_OBJ_GET_REQ:
		rpc_handle_obj_get(ep, (dsosd_msg_obj_get_req_t *)msg, len);
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

static int idx_rbn_cmp_fn(void *tree_key, void *key)
{
	return strcmp(tree_key, key);
}

static int handle_rbn_cmp_fn(void *tree_key, void *key)
{
	return (uint64_t)tree_key - (uint64_t)key;
}

dsosd_client_t *dsosd_client_new(zap_ep_t ep)
{
	dsosd_client_t	*client;

	client = (dsosd_client_t *)calloc(1, sizeof(dsosd_client_t));
	if (!client)
		dsosd_fatal("out of memory");

	client->refcount    = 1;  // start with a reference
	client->ep          = ep;
	client->next_handle = 0x1b0b0b0b0ul;

	pthread_mutex_init(&client->idx_rbt_lock, 0);
	sem_init(&client->initialized_sem, 0, 0);
	rbt_init(&client->idx_rbt, idx_rbn_cmp_fn);
	rbt_init(&client->handle_rbt, handle_rbn_cmp_fn);
#if 1
	/*
	 * XXX Until SOS can provide for RMA directly to or from a
	 * container-backed object, each client allocates a heap for
	 * RMA. For object creation, new objects are RMA-read from
	 * the client into this heap and then copied into the actual
	 * SOS object. For object retrieval, existing SOS objects are
	 * copied into this heap and then RMA-written to the client.
	 */
	client->heap_sz  = 4 * 1024 * 1024;
	client->heap_buf = malloc(client->heap_sz);
	if (!client->heap_buf) {
		dsosd_client_put(client);
		return NULL;
	}
#endif
	return client;
}

void dsosd_client_get(dsosd_client_t *client)
{
	ods_atomic_inc(&client->refcount);
	dsosd_debug("%p refcount now %d\n", client, client->refcount);
}

void dsosd_client_put(dsosd_client_t *client)
{
	struct ptr_rbn	*rbn;

	dsosd_debug("%p refcount was %d\n", client, client->refcount);
	if (!ods_atomic_dec(&client->refcount)) {
#if 1
		// XXX
		if (client->lmap)
			zap_unmap(client->ep, client->lmap);
		if (client->heap_buf)
			free(client->heap_buf);
#endif
		while ((rbn = (struct ptr_rbn *)rbt_min(&client->handle_rbt))) {
			rbt_del(&client->handle_rbt, (struct rbn *)rbn);
			free(rbn);
		}
#if 1
		client->debug = 0xbadb0bad;
#endif
		free(client);
	}
}

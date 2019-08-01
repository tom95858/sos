#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <assert.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netdb.h>
#include "dsosd_priv.h"
#include "dsos_rpc_msg.h"

struct globals_s	g;

static void	dsosd_log(const char *fmt, ...);
static void	handle_connect_err(zap_ep_t ep);
static void	handle_connect_req(zap_ep_t ep);
static void	handle_connected(zap_ep_t ep);
static void	handle_disconnected(zap_ep_t ep);
static void	handle_msg(zap_ep_t ep, dsos_msg_t *msg, size_t len);
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
	dsos_msg_t	*msg;
	dsosd_client_t	*client = (dsosd_client_t *)zap_get_ucontext(ep);

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
		msg = (dsos_msg_t *)ev->data;
		if (client->msg.allocated) {
			/*
			 * Message #2 or later of a multiple-message RPC.
			 * Concatenate it onto the buffer allocated after
			 * seeing message #1.
			 */
			memcpy(client->msg.p, msg, ev->data_len);
			client->msg.p         += ev->data_len;
			client->msg.allocated -= ev->data_len;
			dsosd_debug("client %p: next msg len %d copied to %p, %d left\n", client,
				    ev->data_len, client->msg.msg, client->msg.allocated);
			if (client->msg.allocated <= 0)  {
				handle_msg(ep, (dsos_msg_t *)client->msg.msg, client->msg.len);
				if (client->msg.free_fn)
					client->msg.free_fn(client->msg.msg);
				client->msg.allocated = 0;
			}
		} else if (msg->hdr.flags & DSOS_RPC_FLAGS_MULTIPLE) {
			/*
			 * Message #1 of a multiple-message RPC. Allocate a
			 * buffer to hold the whole thing and arrange for copying the
			 * received message frames into the buffer.
			 */
			client->msg.len       = msg->hdr.len;
			client->msg.msg       = (dsos_msg_t *)dsosd_malloc(client->msg.len);
			client->msg.p         = (char *)client->msg.msg;
			client->msg.allocated = client->msg.len;
			client->msg.free_fn   = free;

			memcpy(client->msg.p, ev->data, ev->data_len);
			client->msg.p         += ev->data_len;
			client->msg.allocated -= ev->data_len;
			dsosd_debug("client %p: msg #1 len %d of %d copied to %p, %d left\n", client,
				    ev->data_len, client->msg.len, client->msg.msg, client->msg.allocated);
			break;
		} else {
			/* An RPC that fits within a single message. */
			handle_msg(ep, msg, ev->data_len);
		}
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
// the rma-read from the client is complete, finish the rpc
static void handle_read_complete(zap_ep_t ep, void *ctxt)
{
	int		ret;
	char		*obj_data;
	size_t		obj_sz;
	dsosd_rpc_t	*rpc = (dsosd_rpc_t *)ctxt;
	sos_obj_t	obj  = (sos_obj_t)rpc->ctxt;
	dsosd_client_t	*client = (dsosd_client_t *)zap_get_ucontext(ep);

#if 1
	/* Remove this once SOS can map objects directly. */
	sos_obj_data_get(obj, &obj_data, &obj_sz);
	memcpy(obj_data, rpc->rma_buf, obj_sz);
	mm_free(client->heap, rpc->rma_buf);
#endif
	*(uint64_t *)obj_data = sos_schema_id(obj->schema);

	ret = sos_obj_index(obj);
	if (ret)
		dsosd_error("rpc %p obj %p sos_obj_index ret %d\n", rpc, obj, ret);

	sos_obj_put(obj);
	++g.stats.tot_num_obj_creates_rma;

	dsosd_debug("rpc %p new obj %p rma-read complete sos_obj_index %d\n", rpc, obj, ret);

	dsosd_rpc_complete(rpc, ret);
}

// we get here as part of an RMA-write of a SOS obj to the client
// the rma-write to the client is complete, finish the rpc
static void handle_write_complete(zap_ep_t ep, void *ctxt)
{
	dsosd_rpc_t	*rpc = (dsosd_rpc_t *)ctxt;
	sos_obj_t	obj  = (sos_obj_t)rpc->ctxt;
	dsosd_client_t	*client = (dsosd_client_t *)zap_get_ucontext(ep);

	dsosd_debug("rpc %p obj %p rma-write complete\n", rpc, obj);
#if 1
	/* Remove this once SOS can map objects directly. */
	mm_free(client->heap, rpc->rma_buf);
	rpc->rma_buf = NULL;
#endif
	sos_obj_put(obj);
	++g.stats.tot_num_obj_gets_rma;
	dsosd_rpc_complete(rpc, 0);
}

static void handle_msg(zap_ep_t ep, dsos_msg_t *msg, size_t len)
{
	dsosd_rpc_t	*rpc;
	dsosd_client_t	*client = (dsosd_client_t *)zap_get_ucontext(ep);

	if (!client->initialized) {
		dsosd_debug("ep %p client %p waiting for init\n", ep, client);
		sem_wait(&client->initialized_sem);
		client->initialized = 1;
	}

	++g.stats.tot_num_reqs;

	rpc = dsosd_rpc_new(client, msg, len);

	switch (msg->hdr.type) {
	    case DSOS_RPC_PING:
		rpc_handle_ping(rpc);
		break;
	    case DSOS_RPC_CONT_NEW:
		rpc_handle_cont_new(rpc);
		break;
	    case DSOS_RPC_CONT_OPEN:
		rpc_handle_cont_open(rpc);
		break;
	    case DSOS_RPC_CONT_CLOSE:
		rpc_handle_cont_close(rpc);
		break;
	    case DSOS_RPC_ITER_CLOSE:
		rpc_handle_iter_close(rpc);
		break;
	    case DSOS_RPC_ITER_NEW:
		rpc_handle_iter_new(rpc);
		break;
	    case DSOS_RPC_ITER_STEP:
		rpc_handle_iter_step(rpc);
		break;
	    case DSOS_RPC_OBJ_CREATE:
		rpc_handle_obj_create(rpc);
		break;
	    case DSOS_RPC_OBJ_DELETE:
		rpc_handle_obj_delete(rpc);
		break;
	    case DSOS_RPC_OBJ_GET:
		rpc_handle_obj_get(rpc);
		break;
	    case DSOS_RPC_PART_CREATE:
		rpc_handle_part_create(rpc);
		break;
	    case DSOS_RPC_PART_FIND:
		rpc_handle_part_find(rpc);
		break;
	    case DSOS_RPC_PART_SET_STATE:
		rpc_handle_part_set_state(rpc);
		break;
	    case DSOS_RPC_SCHEMA_FROM_TEMPLATE:
		rpc_handle_schema_from_template(rpc);
		break;
	    case DSOS_RPC_SCHEMA_ADD:
		rpc_handle_schema_add(rpc);
		break;
	    case DSOS_RPC_SCHEMA_BY_NAME:
		rpc_handle_schema_by_name(rpc);
		break;
	    case DSOS_RPC_SCHEMA_BY_ID:
		rpc_handle_schema_by_id(rpc);
		break;
	    case DSOS_RPC_SCHEMA_FIRST:
		rpc_handle_schema_first(rpc);
		break;
	    case DSOS_RPC_SCHEMA_NEXT:
		rpc_handle_schema_next(rpc);
		break;
	    case DSOS_RPC_FILTER_NEW:
		rpc_handle_filter_new(rpc);
		break;
	    case DSOS_RPC_FILTER_FREE:
		rpc_handle_filter_free(rpc);
		break;
	    case DSOS_RPC_FILTER_STEP:
		rpc_handle_filter_step(rpc);
		break;
	    case DSOS_RPC_FILTER_COND_ADD:
		rpc_handle_filter_cond_add(rpc);
		break;
	    case DSOS_RPC_FILTER_MISS_COUNT:
		rpc_handle_filter_miss_count(rpc);
		break;
	    case DSOS_RPC_FILTER_FLAGS_GET:
		rpc_handle_filter_flags_get(rpc);
		break;
	    case DSOS_RPC_FILTER_FLAGS_SET:
		rpc_handle_filter_flags_set(rpc);
		break;
	    default:
		dsosd_error("unhandled msg type %d rpc %p ep %p\n", msg->hdr.type, rpc, ep);
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

	client->refcount      = 1;  // start with a reference
	client->ep            = ep;
	client->next_handle   = 0x1b0b0b0b0ul;
	client->msg.msg       = NULL;
	client->msg.p         = NULL;
	client->msg.len       = 0;
	client->msg.allocated = 0;
	client->msg.free_fn   = NULL;

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

static int handle_traverse_dump(struct rbn *rbn, void *ctxt, int level)
{
	struct ptr_rbn		*rbn_ptr = (struct ptr_rbn *)rbn;

	dsosd_debug("client %p handle for %s 0x%lx => %p still open\n",
		    ctxt,
		    dsosd_handle_type_str(rbn_ptr->type),
		    rbn_ptr->rbn.key,
		    rbn_ptr->ptr);
}

static int handle_traverse_close(struct rbn *rbn, void *ctxt, int level)
{
	dsosd_handle_type_t	to_close = (dsosd_handle_type_t)ctxt;
	struct ptr_rbn		*rbn_ptr = (struct ptr_rbn *)rbn;

	if (rbn_ptr->type != to_close)
		return 0;

	switch (rbn_ptr->type) {
	    case DSOSD_HANDLE_CONT:
		dsosd_debug("closing container %p\n", rbn_ptr->ptr);
		sos_container_close((sos_t)rbn_ptr->ptr, SOS_COMMIT_SYNC);
		break;
	    case DSOSD_HANDLE_ITER:
		dsosd_debug("closing iterator %p\n", rbn_ptr->ptr);
		sos_iter_free((sos_iter_t)rbn_ptr->ptr);
		break;
	    case DSOSD_HANDLE_PART:
	    case DSOSD_HANDLE_SCHEMA:
	    case DSOSD_HANDLE_FILTER:
	    case DSOSD_HANDLE_INDEX:
		break;
	}
}

void dsosd_client_put(dsosd_client_t *client)
{
	struct rbn	*rbn;

	dsosd_debug("%p refcount was %d\n", client, client->refcount);
	if (!ods_atomic_dec(&client->refcount)) {
#if 1
		// XXX
		if (client->lmap)
			zap_unmap(client->ep, client->lmap);
		if (client->heap_buf)
			free(client->heap_buf);
#endif
#ifdef DSOSD_DEBUG
		rbt_traverse(&client->handle_rbt, handle_traverse_dump, client);
#endif

		/* Close all open iterators. */
		rbt_traverse(&client->handle_rbt, handle_traverse_close, (void *)DSOSD_HANDLE_ITER);

		/* Close all open containers. */
		rbt_traverse(&client->handle_rbt, handle_traverse_close, (void *)DSOSD_HANDLE_CONT);

		/* Free the handle rbt. */
		while (rbn = rbt_min(&client->handle_rbt)) {
			rbt_del(&client->handle_rbt, rbn);
			free(rbn);
		}
		free(client);
		dsosd_debug("%p freed\n", client);
	}
}

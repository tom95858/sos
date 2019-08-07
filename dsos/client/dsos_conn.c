#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ods/rbt.h>
#include "dsos_priv.h"

static void client_cb(zap_ep_t ep, zap_event_t ev)
{
	dsos_msg_t	*msg;
	dsos_conn_t	*conn = (dsos_conn_t *)zap_get_ucontext(ep);

	switch (ev->type) {
	    case ZAP_EVENT_CONNECTED:
	    {
#ifdef DSOS_DEBUG
		struct sockaddr_in	lsin;
		struct sockaddr_in	rsin;
		socklen_t		slen;
		char			mybuf[16];

		slen = sizeof(rsin);
		zap_get_name(ep, (void *)&lsin, (void *)&rsin, &slen);
		inet_ntop(rsin.sin_family, &rsin.sin_addr, mybuf, sizeof(mybuf));
		dsos_debug("connected: %s:%d (rsin)\n", mybuf, ntohs(rsin.sin_port));
		inet_ntop(lsin.sin_family, &lsin.sin_addr, mybuf, sizeof(mybuf));
		dsos_debug("connected: %s:%d (lsin)\n", mybuf, ntohs(rsin.sin_port));
#endif
		conn->conn_status = 0;
		sem_post(&conn->conn_sem);
		break;
	    }
	    case ZAP_EVENT_DISCONNECTED:
		dsos_debug("ZAP_EVENT_DISCONNECTED ep %p conn %p\n", ep, conn);
		sem_post(&conn->conn_sem);
		break;
	    case ZAP_EVENT_REJECTED:
	    case ZAP_EVENT_CONNECT_ERROR:
		dsos_error("connect error ep %p status %d\n", ep, ev->status);
		conn->conn_status = ev->status;
		sem_post(&conn->conn_sem);
		break;
	    case ZAP_EVENT_RECV_COMPLETE:
		msg = (dsos_msg_t *)ev->data;
		if (conn->msg.allocated) {
			/*
			 * Message #2 or later of a multiple-message RPC.
			 * Concatenate it onto the buffer allocated after
			 * seeing message #1.
			 */
			memcpy(conn->msg.p, msg, ev->data_len);
			conn->msg.p         += ev->data_len;
			conn->msg.allocated -= ev->data_len;
			dsos_debug("server %d: next msg len %d copied to %p, %d left\n", conn->server_id,
				    ev->data_len, conn->msg.msg, conn->msg.allocated);
			if (conn->msg.allocated <= 0)  {
				dsos_rpc_handle_resp(conn, (dsos_msg_t *)conn->msg.msg, conn->msg.len);
				if (conn->msg.free_fn)
					conn->msg.free_fn(conn->msg.msg);
				conn->msg.allocated = 0;
			}
		} else if (msg->hdr.flags & DSOS_RPC_FLAGS_MULTIPLE) {
			/*
			 * Message #1 of a multiple-message RPC. Allocate a
			 * buffer to hold the whole thing and arrange for copying the
			 * received message frames into the buffer.
			 */
			conn->msg.len       = msg->hdr.len;
			conn->msg.msg       = (dsos_msg_t *)dsos_malloc(conn->msg.len);
			conn->msg.p         = (char *)conn->msg.msg;
			conn->msg.allocated = conn->msg.len;
			conn->msg.free_fn   = free;

			memcpy(conn->msg.p, ev->data, ev->data_len);
			conn->msg.p         += ev->data_len;
			conn->msg.allocated -= ev->data_len;
			dsos_debug("server %d: msg #1 len %d of %d copied to %p, %d left\n", conn->server_id,
				   ev->data_len, conn->msg.len, conn->msg.msg, conn->msg.allocated);
			break;
		} else {
			/* A single-message RPC. */
			dsos_rpc_handle_resp(conn, msg, ev->data_len);
		}
		break;
	    case ZAP_EVENT_READ_COMPLETE:
	    case ZAP_EVENT_WRITE_COMPLETE:
		break;
	    case ZAP_EVENT_RENDEZVOUS:
		break;
	    default:
		dsos_error("unhandled event %s\n", zap_event_str(ev->type));
		break;
	}
	dsos_debug("done\n");
}

int dsos_connect(const char *host, const char *service, int server_id, int wait)
{
	int			ret;
	zap_err_t		zerr;
	dsos_conn_t		*conn;
	struct sockaddr_in	sin;
	struct addrinfo		*ai;

	conn = &g.conns[server_id];
	if (conn->ep)
		return EISCONN;
	conn->ep = zap_new(g.zap, client_cb);
	if (!conn->ep)
		return ENOMEM;
	zap_set_ucontext(conn->ep, conn);
	sem_init(&conn->rpc_credit_sem, 0, SQ_DEPTH);
	conn->server_id = server_id;
	conn->host      = strdup(host);
	conn->service   = strdup(service);

	ret = getaddrinfo(conn->host, conn->service, NULL, &ai);
	if (ret)
		dsos_fatal("getaddrinfo error %d %s\n", ret, gai_strerror(ret));
	sin = *(struct sockaddr_in *)ai[0].ai_addr;
	freeaddrinfo(ai);

	sem_init(&conn->conn_sem, 0, 0);
	conn->conn_status = 0;
	zerr = zap_connect(conn->ep, (struct sockaddr *)&sin, sizeof(sin), NULL, 0);
	if (zerr) {
		dsos_error("could not connect to server %s:%s zerr %d %s\n",
			   host, service, zerr, zap_err_str(zerr));
		return zerr;
	}
	if (wait) {
		sem_wait(&conn->conn_sem);
		return conn->conn_status;
	}
	return 0;
}

void dsos_disconnect(void)
{
	int		i, ret;
	zap_err_t	zerr;

	dsos_debug("starting\n");
	for (i = 0; i < g.num_servers; ++i) {
		sem_init(&g.conns[i].conn_sem, 0, 0);
		ret = zap_close(g.conns[i].ep);
		if (ret)
			dsos_error("disconnect err %d\n", ret);
	}
	for (i = 0; i < g.num_servers; ++i) {
		sem_wait(&g.conns[i].conn_sem);
		zap_free(g.conns[i].ep);
	}
	dsos_debug("done\n");
}

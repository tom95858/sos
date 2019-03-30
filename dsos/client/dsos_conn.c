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
	dsos_req_t		*req;
	dsosd_msg_t		*resp;
	struct sockaddr_in	lsin = {0};
	struct sockaddr_in	rsin = {0};
	socklen_t		slen;
	char			mybuf[16];
	dsos_conn_t		*conn = (dsos_conn_t *)zap_get_ucontext(ep);

	switch (ev->type) {
	    case ZAP_EVENT_CONNECTED:
		slen = sizeof(rsin);
		zap_get_name(ep, (void *)&lsin, (void *)&rsin, &slen);
		inet_ntop(rsin.sin_family, &rsin.sin_addr, mybuf, sizeof(mybuf));
		dsos_debug("connected: %s:%d (rsin)\n", mybuf, ntohs(rsin.sin_port));
		inet_ntop(lsin.sin_family, &lsin.sin_addr, mybuf, sizeof(mybuf));
		dsos_debug("connected: %s:%d (lsin)\n", mybuf, ntohs(rsin.sin_port));

		conn->conn_status = 0;
		sem_post(&conn->conn_sem);
		break;
	    case ZAP_EVENT_DISCONNECTED:
		// We're disconnected from a server. This probably is fatal
		// for the client.
		// XXX
		zap_free(ep);
		break;
	    case ZAP_EVENT_REJECTED:
	    case ZAP_EVENT_CONNECT_ERROR:
		dsos_error("connect error ep %p\n", ep);
		zap_free(ep);
		conn->conn_status = ev->status;
		sem_post(&conn->conn_sem);
		break;
	    case ZAP_EVENT_RECV_COMPLETE:
		resp = (dsosd_msg_t *)ev->data;
		req = dsos_req_find(resp);
		dsos_debug("ZAP_EVENT_RECV_COMPLETE resp %p len %d id %ld type %d status %d flags 0x%x conn %p req %p\n",
			   resp, ev->data_len, resp->u.hdr.id, resp->u.hdr.type, resp->u.hdr.status, resp->u.hdr.flags,
			   conn, req);
		if (!req)  {
			dsos_error("no req for id %ld\n", resp->u.hdr.id);
			break;
		}
		// On send, req->msg points to a send buffer (malloc'd by dsos_req_new but
		// eventually to be provided by zap_send_alloc()) which is invalid after the
		// send is posted by dsos_req_submit(). Here, req->resp points to the response
		// that just came in. That buffer is invalid after the callback below returns.
		// So if this response is part of an N-fanout request, that request's callback
		// won't get called until later so that callback is responsible for copying
		// the response. This is acceptable because these are for slow-path operations.
		req->resp_len = ev->data_len;
		req->cb(req, ev->data_len, req->ctxt);
		// Don't be tempted to call dsos_req_put() now. For an N-fanout req it needs
		// to live until the req_all is complete.
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
}

int dsos_connect(const char *host, const char *service, int server_id)
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
	sem_init(&conn->flow_sem, 0, SQ_DEPTH);
	conn->server_id = server_id;
	conn->host      = strdup(host);
	conn->service   = strdup(service);

	ret = getaddrinfo(conn->host, conn->service, NULL, &ai);
	if (ret)
		dsos_fatal("getaddrinfo error %d %s\n", ret, gai_strerror(ret));
	sin = *(struct sockaddr_in *)ai[0].ai_addr;
	freeaddrinfo(ai);

	sem_init(&conn->conn_sem, 0, 0);
	zerr = zap_connect(conn->ep, (struct sockaddr *)&sin, sizeof(sin), NULL, 0);
	if (zerr) {
		dsos_error("could not connect to server %s:%s err %s\n",
			   host, service, zap_err_str(zerr));
		return 1;
	}
	sem_wait(&conn->conn_sem);

	return conn->conn_status;
}

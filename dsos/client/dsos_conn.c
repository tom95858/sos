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

const char *dsos_msg_type_to_str(int id)
{
	switch (id) {
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
	    case DSOSD_MSG_CONTAINER_CLOSE_REQ:
		return "DSOSD_CONTAINER_CLOSE_REQ";
	    case DSOSD_MSG_CONTAINER_CLOSE_RESP:
		return "DSOSD_CONTAINER_CLOSE_RESP";
	    case DSOSD_MSG_CONTAINER_DELETE_REQ:
		return "DSOSD_CONTAINER_DELETE_REQ";
	    case DSOSD_MSG_CONTAINER_DELETE_RESP:
		return "DSOSD_CONTAINER_DELETE_RESP";
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
	    case DSOSD_MSG_OBJ_INDEX_REQ:
		return "DSOSD_OBJ_INDEX_REQ";
	    case DSOSD_MSG_OBJ_INDEX_RESP:
		return "DSOSD_OBJ_INDEX_RESP";
	    case DSOSD_MSG_OBJ_FIND_REQ:
		return "DSOSD_OBJ_FIND_REQ";
	    case DSOSD_MSG_OBJ_FIND_RESP:
		return "DSOSD_OBJ_FIND_RESP";
	    case DSOSD_MSG_OBJ_GET_REQ:
		return "DSOSD_OBJ_GET_REQ";
	    case DSOSD_MSG_OBJ_GET_RESP:
		return "DSOSD_OBJ_GET_RESP";
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

static void client_cb(zap_ep_t ep, zap_event_t ev)
{
	dsos_req_t	*req;
	dsosd_msg_t	*resp;
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
		resp = (dsosd_msg_t *)ev->data;
		req = dsos_req_find(resp);
		dsos_debug("ZAP_EVENT_RECV_COMPLETE %s srv %d req %p resp %p len %d "
			   "id %ld type %d status %d flags 0x%x conn %p\n",
			   dsos_msg_type_to_str(resp->u.hdr.type), conn->server_id,
			   req, resp, ev->data_len, resp->u.hdr.id, resp->u.hdr.type,
			   resp->u.hdr.status, resp->u.hdr.flags, conn);
		if (!req)
			dsos_fatal("no req for id %ld from server %d\n", resp->u.hdr.id, conn->server_id);
		// On send, req->msg points to a send buffer (malloc'd by dsos_req_new but
		// eventually to be provided by zap_send_alloc()) which is invalid after the
		// send is posted by dsos_req_submit(). Here, req->resp points to the response
		// that just came in. That buffer is invalid after the callback below returns.
		req->resp_len = ev->data_len;
		req->cb(req, ev->data_len, req->ctxt);
		// Don't be tempted to call dsos_req_put() now. For a vector-RPC req it needs
		// to live until the dsos_req_all_t is complete.
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
		zerr = zap_unmap(g.conns[i].ep, g.conns[i].map);
		if (zerr)
			dsos_error("unmap err %d\n", zerr);
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

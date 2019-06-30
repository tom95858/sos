#ifndef __DSOSD_PRIV_H
#define __DSOSD_PRIV_H

#include <pthread.h>
#include <semaphore.h>
#include <sys/queue.h>
#include <errno.h>
#include <assert.h>
#include <zap.h>
#include "mmalloc.h"
#include "dsosd_msg_layout.h"
#include "sos_priv.h"

/* Options. */
struct opts_s {
	char	*zap_prov_name;   // name of zap provider to use
	char	*src_addr;        // local addr of listening endpoint
	char	*src_port;        // port or service name of listening endpoint
	int	daemon;		  // run in the background
	int	server_num;       // this server's # within DSOS (0..N-1)
};

/* Server statistics. */
struct dsosd_stats_s {
	int	tot_num_connects;
	int	tot_num_disconnects;
	int	tot_num_reqs;
	int	*q_depths;
	int	*num_worker_reqs;
};

/*
 * Global variables. Put them into a C struct to encapsulate them into
 * a name space, like g.opts.daemon for example.
 */
struct globals_s {
	struct opts_s		opts;          // cmd-line options
	int			num_clients;   // # connected clients
	struct dsosd_stats_s	stats;         // server statistics
	zap_t			zap;           // zap transport
	zap_ep_t		ep;            // zap listening endpoint
	sem_t			exit_sem;      // signal this to exit dsosd
};
extern struct globals_s g;

typedef struct dsosd_client_s	dsosd_client_t;
typedef struct dsosd_req_s	dsosd_req_t;

/*
 * A client work request. This is created when an incoming message is
 * received and maintains the request state throughout the request's
 * lifetime.
 */
typedef struct dsosd_req_s {
	ods_atomic_t		refcount;
	dsosd_client_t		*client;
	dsosd_msg_t		*resp;         // response message
	size_t			resp_max_len;  // size allocated for resp msg
	size_t			resp_len;      // actual response msg size
	void			*ctxt;
#if 1
	// The following field goes away once SOS can map the ODS maps
	// so objects can be RMA'd directly.
	void			*rma_buf;      // XXX buf from registered heap (temporary)
#endif
} dsosd_req_t;

/* Red-black tree node to map a string to a pointer. */
struct ptr_rbn {
	struct rbn	rbn;
	void		*ptr;
};

/*
 * Client object. This encapsulates all state created on behalf of the
 * client. There are two heaps. One is on the client and is shared
 * with every server. The other is on the server and is used for
 * object RMA to/from the client heap; the server heap may go away in
 * the future if SOS can be enhanced for RMA.
 */
typedef struct dsosd_client_s {
	ods_atomic_t		refcount;
	zap_ep_t		ep;            // zap active endpoint
	zap_map_t		rmap;          // map for shared client heap
	struct rbt		idx_rbt;       // maps idx name -> sos_index_t
	pthread_mutex_t		idx_rbt_lock;
	struct rbt		handle_rbt;    // maps handles to pointers
	uint64_t		next_handle;   // next handle # to give out
	int			initialized;   // set when endpoint is ready
	sem_t			initialized_sem;
	int			debug;
#if 1
	// XXX temporary, until SOS can alloc from reg mem
	mm_region_t		heap;          // mapped heap for object RMA
	zap_map_t		lmap;          // local map
	char			*heap_buf;     // mapped buffer for heap
	size_t			heap_sz;       // size of mapped heap
#endif
} dsosd_client_t;

void		dsosd_client_get(dsosd_client_t *client);
dsosd_client_t	*dsosd_client_new(zap_ep_t ep);
void		dsosd_client_put(dsosd_client_t *client);
dsosd_objid_t	dsosd_objid(sos_obj_t sos_obj);
zap_err_t	dsosd_req_complete(dsosd_req_t *req, size_t len);
void		dsosd_req_get(dsosd_req_t *req);
dsosd_req_t	*dsosd_req_new(dsosd_client_t *client, uint16_t type, uint64_t msg_id, size_t msg_len);
void		dsosd_req_put(dsosd_req_t *req);
char		*str_replace(char *orig, char *rep, char *with);

sos_schema_template_t	rpc_deserialize_schema_template(char *buf, size_t len);
void		rpc_handle_container_open(zap_ep_t ep, dsosd_msg_container_open_req_t *msg, size_t len);
void		rpc_handle_container_close(zap_ep_t ep, dsosd_msg_container_close_req_t *msg, size_t len);
void		rpc_handle_container_new(zap_ep_t ep, dsosd_msg_container_new_req_t *msg, size_t len);
void		rpc_handle_obj_create(zap_ep_t ep, dsosd_msg_obj_create_req_t *msg, size_t len);
void		rpc_handle_obj_delete(zap_ep_t ep, dsosd_msg_obj_delete_req_t *msg, size_t len);
void		rpc_handle_obj_get(zap_ep_t ep, dsosd_msg_obj_get_req_t *msg, size_t len);
void		rpc_handle_part_create(zap_ep_t ep, dsosd_msg_part_create_req_t *msg, size_t len);
void		rpc_handle_part_find(zap_ep_t ep, dsosd_msg_part_find_req_t *msg, size_t len);
void		rpc_handle_part_set_state(zap_ep_t ep, dsosd_msg_part_set_state_req_t *msg, size_t len);
void		rpc_handle_ping(zap_ep_t ep, dsosd_msg_ping_req_t *msg, size_t len);
void		rpc_handle_schema_add(zap_ep_t ep, dsosd_msg_schema_add_req_t *msg, size_t len);
void		rpc_handle_schema_by_name(zap_ep_t ep, dsosd_msg_schema_by_name_req_t *msg, size_t len);
void		rpc_handle_schema_from_template(zap_ep_t ep, dsosd_msg_schema_from_template_req_t *msg, size_t len);

#define dsosd_debug(fmt, ...)	sos_log(SOS_LOG_DEBUG, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define dsosd_error(fmt, ...)	sos_log(SOS_LOG_ERROR, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define dsosd_fatal(fmt, ...) \
	do {									\
		if (!__ods_log_fp)						\
			__ods_log_fp = stderr;					\
		__ods_log_mask = 0xff;						\
		sos_log(SOS_LOG_FATAL, __func__, __LINE__, fmt, ##__VA_ARGS__);	\
		assert(0);							\
	} while (0);

#endif

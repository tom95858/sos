#ifndef __DSOSD_PRIV_H
#define __DSOSD_PRIV_H

#include <pthread.h>
#include <semaphore.h>
#include <sys/queue.h>
#include <errno.h>
#include <assert.h>
#include <zap.h>
#include "mmalloc.h"
#include <dsos/dsos.h>
#include "sos_priv.h"
#include "dsos_pack.h"

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
	int	tot_num_obj_creates_inline;
	int	tot_num_obj_creates_rma;
	int	tot_num_obj_gets_inline;
	int	tot_num_obj_gets_rma;
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

/*
 * A client RPC request. This is created when an incoming message is
 * received and maintains the request state throughout the request's
 * lifetime.
 */
typedef struct dsosd_rpc_s {
	ods_atomic_t		refcount;
	dsosd_client_t		*client;
	dsos_buf_t		req;           // request msg (from client)
	dsos_buf_t		resp;          // response msg (to client)
	void			*ctxt;
	void			*rma_buf;      // buf from shared heap
	int			rma_len;       // len of buf
} dsosd_rpc_t;

/* Red-black tree node to map a string to a pointer. */
typedef enum {
	DSOSD_HANDLE_CONT,
	DSOSD_HANDLE_PART,
	DSOSD_HANDLE_SCHEMA,
	DSOSD_HANDLE_ITER,
	DSOSD_HANDLE_FILTER,
	DSOSD_HANDLE_INDEX,
} dsosd_handle_type_t;
struct ptr_rbn {
	struct rbn	rbn;
	void		*ptr;
	int		type;
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
#if 1
	// XXX temporary, until SOS can alloc from reg mem
	mm_region_t		heap;          // mapped heap for object RMA
	zap_map_t		lmap;          // local map
	char			*heap_buf;     // mapped buffer for heap
	size_t			heap_sz;       // size of mapped heap
#endif
	dsos_buf_t		msg;           // buf for multi-message RPCs
} dsosd_client_t;

void		dsosd_client_get(dsosd_client_t *client);
dsosd_client_t	*dsosd_client_new(zap_ep_t ep);
void		dsosd_client_put(dsosd_client_t *client);

zap_err_t	dsosd_rpc_complete(dsosd_rpc_t *rpc, int status);
void		dsosd_rpc_complete_with_obj(dsosd_rpc_t *rpc, sos_obj_t obj, uint64_t obj_remote_va);
void		dsosd_rpc_get(dsosd_rpc_t *rpc);
dsosd_rpc_t	*dsosd_rpc_new(dsosd_client_t *client, dsos_msg_t *msg, size_t len);
void		dsosd_rpc_put(dsosd_rpc_t *rpc);

dsos_handle_t	dsosd_ptr_to_handle(dsosd_rpc_t *rpc, void *ptr, dsosd_handle_type_t type);
void		*dsosd_handle_to_ptr(dsosd_rpc_t *rpc, dsos_handle_t handle, dsosd_handle_type_t type);
void		dsosd_handle_free(dsosd_rpc_t *rpc, dsos_handle_t handle);
const char	*dsosd_handle_type_str(dsosd_handle_type_t type);

void		rpc_handle_cont_open(dsosd_rpc_t *rpc);
void		rpc_handle_cont_close(dsosd_rpc_t *rpc);
void		rpc_handle_cont_new(dsosd_rpc_t *rpc);
void		rpc_handle_filter_close(dsosd_rpc_t *rpc);
void		rpc_handle_filter_cond_add(dsosd_rpc_t *rpc);
void		rpc_handle_filter_flags_set(dsosd_rpc_t *rpc);
void		rpc_handle_filter_flags_get(dsosd_rpc_t *rpc);
void		rpc_handle_filter_free(dsosd_rpc_t *rpc);
void		rpc_handle_filter_miss_count(dsosd_rpc_t *rpc);
void		rpc_handle_filter_new(dsosd_rpc_t *rpc);
void		rpc_handle_iter_new(dsosd_rpc_t *rpc);
void		rpc_handle_iter_step(dsosd_rpc_t *rpc);
void		rpc_handle_obj_create(dsosd_rpc_t *rpc);
void		rpc_handle_obj_delete(dsosd_rpc_t *rpc);
void		rpc_handle_obj_get(dsosd_rpc_t *rpc);
void		rpc_handle_part_create(dsosd_rpc_t *rpc);
void		rpc_handle_part_find(dsosd_rpc_t *rpc);
void		rpc_handle_part_set_state(dsosd_rpc_t *rpc);
void		rpc_handle_ping(dsosd_rpc_t *rpc);
void		rpc_handle_schema_add(dsosd_rpc_t *rpc);
void		rpc_handle_schema_by_name(dsosd_rpc_t *rpc);
void		rpc_handle_schema_by_id(dsosd_rpc_t *rpc);
void		rpc_handle_schema_first(dsosd_rpc_t *rpc);
void		rpc_handle_schema_next(dsosd_rpc_t *rpc);
void		rpc_handle_schema_from_template(dsosd_rpc_t *rpc);

sos_attr_t	dsosd_rpc_unpack_attr(dsosd_rpc_t *rpc);
int		dsosd_rpc_pack_fits(dsosd_rpc_t *rpc, int len);
int		dsosd_rpc_pack_handle(dsosd_rpc_t *rpc, dsos_handle_t handle);
int		dsosd_rpc_pack_obj_needs(sos_obj_t obj);
int		dsosd_rpc_pack_obj(dsosd_rpc_t *rpc, sos_obj_t obj);
int		dsosd_rpc_pack_obj_id(dsosd_rpc_t *rpc, sos_obj_ref_t obj_id);
int		dsosd_rpc_pack_schema(dsosd_rpc_t *rpc, sos_schema_t schema);
int		dsosd_rpc_pack_u32(dsosd_rpc_t *rpc, uint32_t val);
dsos_handle_t	dsosd_rpc_unpack_handle(dsosd_rpc_t *rpc);
void		*dsosd_rpc_unpack_handle_to_ptr(dsosd_rpc_t *rpc, dsosd_handle_type_t want_type);
sos_key_t	dsosd_rpc_unpack_key(dsosd_rpc_t *rpc);
uint32_t	dsosd_rpc_unpack_u32(dsosd_rpc_t *rpc);
int		dsosd_rpc_unpack_obj(dsosd_rpc_t *rpc, sos_obj_t obj);
uint64_t	dsosd_rpc_unpack_obj_ptr(dsosd_rpc_t *rpc, uint64_t *plen);
sos_obj_ref_t	dsosd_rpc_unpack_obj_id(dsosd_rpc_t *rpc);
sos_schema_t	dsosd_rpc_unpack_schema(dsosd_rpc_t *rpc);
char		*dsosd_rpc_unpack_str(dsosd_rpc_t *rpc);
sos_value_t	dsosd_rpc_unpack_value(dsosd_rpc_t *rpc);

#define dsosd_debug(fmt, ...)		sos_log(SOS_LOG_DEBUG, __func__, __LINE__, fmt, ##__VA_ARGS__)
#ifdef RPC_DEBUG
#define dsosd_rpc_debug(fmt, ...)	sos_log(SOS_LOG_DEBUG, __func__, __LINE__, fmt, ##__VA_ARGS__)
#else
#define dsosd_rpc_debug(fmt, ...)	do {} while (0)
#endif
#define dsosd_error(fmt, ...)		sos_log(SOS_LOG_ERROR, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define dsosd_fatal(fmt, ...) \
	do {									\
		if (!__ods_log_fp)						\
			__ods_log_fp = stderr;					\
		__ods_log_mask = 0xff;						\
		sos_log(SOS_LOG_FATAL, __func__, __LINE__, fmt, ##__VA_ARGS__);	\
		assert(0);							\
	} while (0);

static inline char *dsosd_malloc(size_t len)
{
	char *ret = malloc(len);
	if (!ret)
		dsosd_fatal("out of memory\n");
	return ret;
}

#endif

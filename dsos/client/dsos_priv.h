#ifndef __DSOS_PRIV_H
#define __DSOS_PRIV_H

#include <pthread.h>
#include <sys/queue.h>
#include <openssl/sha.h>
#include <semaphore.h>
#include <errno.h>
#include <assert.h>
#include <zap.h>
#include <dsos/dsos.h>
#include "sos_priv.h"
#include "json_util.h"
#include "mmalloc.h"
#include "../server/dsos_rpc_msg.h"
#include "dsos_pack.h"

typedef struct dsos_err_s	dsos_err_t;
typedef struct dsos_conn_s	dsos_conn_t;
typedef struct dsos_rpc_s	dsos_rpc_t;
typedef struct dsos_buf_s	dsos_buf_t;
typedef struct dsos_obj_s	dsos_obj_t;
typedef struct dsos_s		dsos_t;
typedef struct dsos_schema_s	dsos_schema_t;
typedef enum dsos_rpc_flags_e	dsos_rpc_flags_t;

typedef void (*dsos_rpc_cb_t) (dsos_rpc_t *, dsos_rpc_flags_t flags, dsos_buf_t *, int, void *);
typedef void (*dsos_obj_cb_t)(sos_obj_t, void *);

typedef struct {
	void	*ptr1;
	void	*ptr2;
} dsos_ptr_tuple_t;

/* This will be a zap_new() parameter eventually. */
#define SQ_DEPTH	4

#define DSOS_DEFAULT_SHARED_HEAP_SZ		48*1024*1024
#define DSOS_DEFAULT_SHARED_HEAP_GRAIN_SZ	32

/* Options. */
struct opts_s {
	char	*zap_prov_name;        // zap provider to use
	size_t	heap_sz;               // heap size in bytes (gets 4k roundup)
	size_t	heap_grain_sz;         // heap min alloc size
};

/*
 * Global variables. Put them into a C struct to encapsulate them into
 * a name space, like g.opts.daemon for example.
 */
struct globals_s {
	json_entity_t		config;            // config as a json tree
	int			num_servers;       // # dsos servers
	struct opts_s		opts;              // options
	dsos_conn_t		*conns;            // array of server connection objects
	zap_t			zap;               // transport
	mm_region_t		heap;              // heap shared w/servers
	size_t			heap_sz;           // size of heap
	char			*heap_buf;         // registered buffer for heap
};
extern struct globals_s g;

/*
 * A vector RPC. This is created in response to the user calling into
 * DSOS and lives throughout the request's lifetime to track its
 * state.
 */

typedef enum dsos_rpc_flags_e {
	DSOS_RPC_ONE			= 0x00000001,
	DSOS_RPC_ALL			= 0x00000002,
	DSOS_RPC_CB_FIRST		= 0x00000004,
	DSOS_RPC_CB_LAST		= 0x00000008,
	DSOS_RPC_CB_ALL			= 0x00000010,
	DSOS_RPC_CB			= DSOS_RPC_CB_ALL,
	DSOS_RPC_WAIT			= 0x00000020,
	DSOS_RPC_PERSIST_RESPONSES	= 0x00000040,
	DSOS_RPC_PUT			= 0x00000080,
} dsos_rpc_flags_t;

typedef struct dsos_rpc_bufs_s {
	dsos_buf_t		req;          // request msg (from client)
	dsos_buf_t		resp;         // response msg (to client)
} dsos_rpc_bufs_t;

typedef struct dsos_rpc_s {
	ods_atomic_t		refcount;
	dsos_rpc_flags_t	flags;
	dsos_err_t		status;        // local zap_send statuses & remote response statuses
	int			server_num;    // for DSOS_RPC_ONE, the server getting the rpc
	int			num_servers;   // # servers getting this rpc
	ods_atomic_t		num_pend;      // # servers still pending
	dsos_rpc_bufs_t		*buf;          // shortcut to bufs[0]
	dsos_rpc_bufs_t		*bufs;         // buffers, one per server
	sem_t			sem;           // for signaling responses
	dsos_rpc_cb_t		cb;            // response callback
	void			*ctxt;         // for callbacks
	dsos_ptr_tuple_t	ctxt2;         // for callbacks
} dsos_rpc_t;

/* Red-black tree to map work-request id to the dsos_rpc_t pointer. */
struct rpc_rbn {
	struct rbn	rbn;
	dsos_rpc_t	*rpc;
};

/*
 * DSOS container object. This encapsulates a vector of container handles,
 * one per server.
 */
typedef struct dsos_s {
	dsos_handle_t	*handles;
} dsos_t;

/*
 * DSOS partition object. This encapsulates a vector of partition handles,
 * one per server.
 */
typedef struct dsos_part_s {
	dsos_handle_t	*handles;
} dsos_part_t;

/*
 * DSOS schema object. This encapsulates a vector of schema handles,
 * one per server.
 */
typedef struct dsos_schema_s {
	dsos_t		*cont;                // container
	dsos_handle_t	*handles;             // vector of server handles
	sos_schema_t	sos_schema;           // local SOS schema handle
} dsos_schema_t;

/*
 * DSOS iteration object.
 */
struct iter_rbn {
	struct rbn	rbn;
	sos_obj_t	obj;
};
typedef struct dsos_iter_s {
	pthread_mutex_t	lock;
	pthread_cond_t	prefetch_complete;
	dsos_schema_t	*schema;
	sos_attr_t	attr;                 // attr this is iterating over
	dsos_handle_t	*handles;             // vector of server sos_iter_t handles
	int		done;                 // =1 when all servers are done w/the iteration
	int		last_op;              // last iter op (begin,end,prev,next)
	int		last_server;          // owning server of the last returned obj
	int		status;               // status of last prefetch
	dsos_rpc_t	*prefetch_rpc;        // rpc of last prefetch
	size_t		obj_sz;               // object size this iterates over
	struct rbt	rbt;                  // for finding min key value of recvd objs
} dsos_iter_t;

/*
 * Connection object.
 */
typedef struct dsos_conn_s {
	int			server_id;      // 0 .. #servers-1
	char			*host;          // server host
	char			*service;       // server port/service
	zap_ep_t		ep;             // zap endpoint
	zap_map_t		map;            // map for client/server shared heap
	int			conn_status;    // connection error status
	sem_t			conn_sem;       // connect semaphore
	sem_t			flow_sem;       // flow-control semaphore
} dsos_conn_t;

/* Internal API. */

void		dsos_rpc_get(dsos_rpc_t *rpc);
void		dsos_rpc_handle_resp(dsos_conn_t *conn, dsos_msg_t *resp, size_t len);
void		dsos_rpc_init(void);
dsos_rpc_t	*dsos_rpc_new(dsos_rpc_flags_t flags, dsos_rpc_type_t type);
void		dsos_rpc_put(dsos_rpc_t *rpc);
int		dsos_rpc_send(dsos_rpc_t *rpc, dsos_rpc_flags_t flags);
int		dsos_rpc_send_cb(dsos_rpc_t *rpc, dsos_rpc_flags_t flags, dsos_rpc_cb_t cb, void *ctxt);
int		dsos_rpc_send_one(dsos_rpc_t *rpc, dsos_rpc_flags_t flags, int server_num);
void		dsos_rpc_set_server(dsos_rpc_t *rpc, int server_num);

int		dsos_rpc_pack_fits(dsos_rpc_t *rpc, int len);
void		dsos_rpc_pack_handle(dsos_rpc_t *rpc, dsos_handle_t handle);
void		dsos_rpc_pack_handles(dsos_rpc_t *rpc, dsos_handle_t *handles);
void		dsos_rpc_pack_key_one(dsos_rpc_t *rpc, sos_key_t key);
void		dsos_rpc_pack_key_all(dsos_rpc_t *rpc, sos_key_t key);
void		dsos_rpc_pack_obj(dsos_rpc_t *rpc, sos_obj_t obj);
void		dsos_rpc_pack_obj_id_all(dsos_rpc_t *rpc, sos_obj_ref_t obj_id);
void		dsos_rpc_pack_obj_id_one(dsos_rpc_t *rpc, sos_obj_ref_t obj_id);
int		dsos_rpc_pack_obj_needs(sos_obj_t obj);
void		dsos_rpc_pack_obj_ptr(dsos_rpc_t *rpc, sos_obj_t obj);
void		dsos_rpc_pack_obj_ptrs(dsos_rpc_t *rpc, sos_obj_t *objs);
void		dsos_rpc_pack_u32_one(dsos_rpc_t *rpc, uint32_t val);
void		dsos_rpc_pack_u32_all(dsos_rpc_t *rpc, uint32_t val);
void		dsos_rpc_pack_u64_one(dsos_rpc_t *rpc, uint64_t val);
void		dsos_rpc_pack_u64_all(dsos_rpc_t *rpc, uint64_t val);
void		dsos_rpc_pack_schema_all(dsos_rpc_t *rpc, sos_schema_t schema);
void		dsos_rpc_pack_str_one(dsos_rpc_t *rpc, const char *str);
void		dsos_rpc_pack_str_all(dsos_rpc_t *rpc, const char *str);
void		dsos_rpc_unpack_buf_and_copy(dsos_rpc_t *rpc, void *to, int *plen);
void		dsos_rpc_unpack_buf_and_copy_one(dsos_rpc_t *rpc, int server_num, void *to, int *plen);
void		dsos_rpc_unpack_bufs_and_copy(dsos_rpc_t *rpc, void *to, int *plen);
dsos_handle_t	*dsos_rpc_unpack_handles(dsos_rpc_t *rpc);
void		dsos_rpc_unpack_obj(dsos_rpc_t *rpc, sos_obj_t obj);
void		dsos_rpc_unpack_obj_one(dsos_rpc_t *rpc, int server_num, sos_obj_t obj);
sos_obj_ref_t	dsos_rpc_unpack_obj_id(dsos_rpc_t *rpc);
sos_obj_ref_t	dsos_rpc_unpack_obj_id_one(dsos_rpc_t *rpc, int server_num);
sos_schema_t	dsos_rpc_unpack_schema_one(dsos_rpc_t *rpc, int server_num);
char		*dsos_rpc_unpack_str(dsos_rpc_t *rpc);
uint32_t	dsos_rpc_unpack_u32(dsos_rpc_t *rpc);
uint32_t	dsos_rpc_unpack_u32_one(dsos_rpc_t *rpc, int server_num);
uint32_t	dsos_rpc_unpack_u64(dsos_rpc_t *rpc);

int		dsos_config_read(const char *config_file);
int		dsos_connect(const char *host, const char *service, int server_id, int wait);
void		dsos_disconnect(void);
void		dsos_err_init(void);
void		dsos_free(void *ptr);
sos_obj_t	dsos_obj_malloc(dsos_schema_t *schema);
sos_obj_t	*dsos_obj_calloc(int num_objs, dsos_schema_t *schema);
const char	*dsos_msg_type_to_str(int id);
int		dsos_obj_server(sos_obj_t obj);

#define dsos_debug(fmt, ...)	sos_log(SOS_LOG_DEBUG, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define dsos_error(fmt, ...)	sos_log(SOS_LOG_ERROR, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define dsos_fatal(fmt, ...) \
	do {									\
		if (!__ods_log_fp)						\
			__ods_log_fp = stderr;					\
		__ods_log_mask = 0xff;						\
		sos_log(SOS_LOG_FATAL, __func__, __LINE__, fmt, ##__VA_ARGS__);	\
		assert(0);							\
	} while (0);

static inline char *dsos_malloc(size_t len)
{
	char *ret = malloc(len);
	if (!ret)
		dsos_fatal("out of memory\n");
	return ret;
}

#endif

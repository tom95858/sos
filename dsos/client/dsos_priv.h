#ifndef __DSOS_PRIV_H
#define __DSOS_PRIV_H

#include <pthread.h>
#include <sys/queue.h>
#include <openssl/sha.h>
#include <semaphore.h>
#include <errno.h>
#include <zap.h>
#include "sos_priv.h"
#include "json_util.h"
#include "mmalloc.h"
#include "../server/dsosd_msg_layout.h"

typedef struct dsos_conn_s	dsos_conn_t;
typedef struct dsos_req_s	dsos_req_t;
typedef struct dsos_req_all_s	dsos_req_all_t;
typedef struct dsos_obj_s	dsos_obj_t;
typedef struct dsos_s		dsos_t;
typedef struct dsos_schema_s	dsos_schema_t;

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
 * A work request. This is created in response to the user calling
 * into DSOS and lives throughout the request's lifetime to track its
 * state.
 */
extern int *REQ_ALL_SERVERS;  // for vector req's
enum {
	REQ_VECTOR_MEMBER  = 0x00000001,
	REQ_RESPONSE_RECVD = 0x00000002,
};
typedef void (*dsos_req_cb_t)(dsos_req_t *, size_t, void *);  // response callback fn
typedef struct dsos_req_s {
	ods_atomic_t		refcount;
	uint32_t		flags;
	uint64_t		id;            // unique id for the request
	dsosd_msg_t		*msg;          // req msg sent to server
	dsosd_msg_t		*resp;         // its response
	size_t			msg_len_max;   // max size of msg (for send)
	size_t			msg_len;       // actual size of msg
	size_t			resp_len;      // actual size of resp (for response)
	dsos_req_cb_t		cb;            // response callback
	void			*ctxt;         // for callbacks
	sem_t			sem;           // for signaling the response
	dsos_conn_t		*conn;         // server connection object
	LIST_ENTRY(dsos_req_s)	entry;         // for dsosd_req_all_t's list
} dsos_req_t;

/*
 * An n-way work request. This is a vector of work requests, one per server.
 */
typedef void (*dsos_req_all_cb_t)(dsos_req_all_t *, void *);  // response callback fn
typedef struct dsos_req_all_s {
	ods_atomic_t		refcount;
	size_t			msg_len_max;   // max size of msg (for send)
	dsos_req_all_cb_t	cb;            // response callback
	void			*ctxt;         // for callbacks
	ods_atomic_t		num_reqs_pend; // # reqs still pending
	int			num_servers;   // # reqs in reqs[]
	dsos_req_t		**reqs;        // all the reqs, one per server
	sem_t			sem;           // for signaling the response
} dsos_req_all_t;

/* Red-black tree to map work-request id to the dsos_req_t pointer. */
struct req_rbn {
	struct rbn	rbn;
	dsos_req_t	*req;
};

/*
 * DSOS container object. This encapsulates a vector of container handles,
 * one per server.
 */
typedef struct dsos_s {
	dsosd_handle_t	*handles;
} dsos_t;

/*
 * DSOS partition object. This encapsulates a vector of partition handles,
 * one per server.
 */
typedef struct dsos_part_s {
	dsosd_handle_t	*handles;
} dsos_part_t;

/*
 * DSOS schema object. This encapsulates a vector of schema handles,
 * one per server.
 */
typedef struct dsos_schema_s {
	dsos_t		*cont;                // container
	dsosd_handle_t	*handles;             // vector of server handles
	sos_schema_t	sos_schema;           // local SOS schema handle
} dsos_schema_t;

/*
 * DSOS iteration object.
 */
struct iter_rbn {
	struct rbn	rbn;
	int		server_num;
};
typedef struct dsos_iter_s {
	dsos_schema_t	*schema;
	sos_attr_t	attr;                 // attr this is iterating over
	dsosd_handle_t	*handles;             // vector of server sos_iter_t handles
	int		done;                 // =1 when all servers are done w/the iteration
	int		last_op;              // last iter op (begin,end,prev,next)
	int		last_srvr;            // server from which the last obj was returned
	size_t		obj_sz;               // object size this iterates over
	sos_obj_t	*sos_objs;            // vector of recvd objs
	struct rbt	rbt;                  // for finding min key value of recvd objs
#if 1
	// The following will go away once sos_obj_malloc() allocs mapped mem.
	void		**rma_bufs;           // mapped mem for rma; temporary for now
#endif
} dsos_iter_t;

/*
 * DSOS object.
 */
typedef enum {
	DSOS_OBJ_INLINE  = 0x00000001,
	DSOS_OBJ_CREATED = 0x00000002
} dsos_obj_type_t;
typedef void (*dsos_obj_cb_t)(dsos_obj_t *, void *);
typedef struct dsos_obj_s {
	dsos_obj_type_t		flags;
	sos_obj_t		sos_obj;       // the actual SOS object
	dsos_schema_t		*schema;
	dsosd_objid_t		obj_id;        // global object id, valid once the resp comes in
	// The following field is temporary until SOS can alloc objs from our shared heap.
	char			*buf;          // pointer to data (shared heap or a send buffer)
	dsos_req_t		*req;          // server req to create this obj
	dsos_req_all_t		*req_all;      // server req(s) to index this obj
	dsos_obj_cb_t		cb;            // response callback
	void			*ctxt;         // for callbacks
} dsos_obj_t;

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

/* Internal RPC API. */

typedef struct {
	char	hello[4];
} rpc_ping_in_t;
typedef struct {
	int	tot_num_connects;
	int	tot_num_disconnects;
	int	tot_num_reqs;
	int	num_clients;
} rpc_ping_out_t;
int	dsos_rpc_ping(rpc_ping_in_t *args_inp,
		      rpc_ping_out_t **args_outpp);

typedef struct {
	char		path[DSOSD_MSG_MAX_PATH];
	uint32_t	mode;
} rpc_container_new_in_t;
typedef struct {
} rpc_container_new_out_t;
int	dsos_rpc_container_new(rpc_container_new_in_t  *args_inp,
			       rpc_container_new_out_t *args_outp);

typedef struct {
	char		path[DSOSD_MSG_MAX_PATH];
	uint32_t	perms;
} rpc_container_open_in_t;
typedef struct {
	dsosd_handle_t	*handles;
} rpc_container_open_out_t;
int	dsos_rpc_container_open(rpc_container_open_in_t  *args_inp,
				rpc_container_open_out_t *args_outp);

typedef struct {
	dsosd_handle_t	*handles;
} rpc_container_close_in_t;
typedef struct {
} rpc_container_close_out_t;
int	dsos_rpc_container_close(rpc_container_close_in_t  *args_inp,
				 rpc_container_close_out_t *args_outp);

typedef struct {
	dsosd_handle_t	*cont_handles;
	dsosd_handle_t	*schema_handles;
} rpc_schema_add_in_t;
typedef struct {
} rpc_schema_add_out_t;
int	dsos_rpc_schema_add(rpc_schema_add_in_t  *args_inp,
			    rpc_schema_add_out_t *args_outp);

typedef struct {
	char		name[DSOSD_MSG_MAX_PATH];
	dsosd_handle_t	*cont_handles;
} rpc_schema_by_name_in_t;
typedef struct {
	dsosd_handle_t	*handles;
	char		templ[DSOSD_MSG_MAX_DATA];
} rpc_schema_by_name_out_t;
int	dsos_rpc_schema_by_name(rpc_schema_by_name_in_t  *args_inp,
				rpc_schema_by_name_out_t *args_outp);

typedef struct {
	uint32_t	len;
	char		templ[DSOSD_MSG_MAX_DATA];
} rpc_schema_from_template_in_t;
typedef struct {
	dsosd_handle_t	*handles;
} rpc_schema_from_template_out_t;
int	dsos_rpc_schema_from_template(rpc_schema_from_template_in_t  *args_inp,
				      rpc_schema_from_template_out_t *args_outp);

typedef struct {
	dsos_obj_t	*obj;
} rpc_object_create_in_t;
typedef struct {
	dsosd_objid_t	obj_id;
} rpc_object_create_out_t;
int	dsos_rpc_object_create(rpc_object_create_in_t *args_inp);

typedef struct {
	char		name[DSOSD_MSG_MAX_PATH];
	char		path[DSOSD_MSG_MAX_PATH];
	dsosd_handle_t	*cont_handles;
} rpc_part_create_in_t;
typedef struct {
} rpc_part_create_out_t;
int	dsos_rpc_part_create(rpc_part_create_in_t  *args_inp,
			     rpc_part_create_out_t *args_outp);

typedef struct {
	int		new_state;
	dsosd_handle_t	*handles;
} rpc_part_set_state_in_t;
typedef struct {
} rpc_part_set_state_out_t;
int	dsos_rpc_part_set_state(rpc_part_set_state_in_t  *args_inp,
				rpc_part_set_state_out_t *args_outp);

typedef struct {
	dsosd_handle_t	*cont_handles;
	char		name[DSOSD_MSG_MAX_PATH];
} rpc_part_find_in_t;
typedef struct {
	dsosd_handle_t	*handles;
} rpc_part_find_out_t;
int	dsos_rpc_part_find(rpc_part_find_in_t  *args_inp,
			   rpc_part_find_out_t *args_outp);

// This RPC is asynchronous, so the results came back via a callback.
typedef struct {
	int		server_num;
	dsos_obj_t	*obj;
	int		num_attrs;
	sos_value_t	*attrs;
} rpc_obj_index_in_t;
int	dsos_rpc_obj_index(rpc_obj_index_in_t *args_inp);

typedef struct {
	int		server_num;
	dsosd_handle_t	cont_handle;
	dsosd_handle_t	schema_handle;
	sos_attr_t	attr;
	sos_key_t	key;
	uint64_t	va;
	uint32_t	len;
} rpc_obj_find_in_t;
typedef struct {
	sos_obj_ref_t	obj_id;
	int		obj_sz;
} rpc_obj_find_out_t;
int	dsos_rpc_obj_find(rpc_obj_find_in_t  *args_inp,
			  rpc_obj_find_out_t *args_outp);

typedef struct {
	dsosd_handle_t	cont_handle;
	sos_obj_ref_t	obj_id;
	uint64_t	va;
	uint32_t	len;
} rpc_obj_get_in_t;
typedef struct {
	int		obj_sz;
} rpc_obj_get_out_t;
int	dsos_rpc_obj_get(rpc_obj_get_in_t  *args_inp,
			 rpc_obj_get_out_t *args_outp);

typedef struct {
	dsosd_handle_t	*schema_handles;
	sos_attr_t	attr;
} rpc_iter_new_in_t;
typedef struct {
	dsosd_handle_t	*handles;
} rpc_iter_new_out_t;
int	dsos_rpc_iter_new(rpc_iter_new_in_t  *args_inp,
			  rpc_iter_new_out_t *args_outp);

typedef struct {
	dsosd_handle_t	*iter_handles;
} rpc_iter_close_in_t;
typedef struct {
} rpc_iter_close_out_t;
int	dsos_rpc_iter_close(rpc_iter_close_in_t  *args_inp,
			    rpc_iter_close_out_t *args_outp);

typedef struct {
	dsosd_handle_t	iter_handle;
	int		op;
	void		*va;
	size_t		obj_sz;
	int		server_num;
} rpc_iter_step_one_in_t;
typedef struct {
	int		found;
} rpc_iter_step_one_out_t;
int	dsos_rpc_iter_step_one(rpc_iter_step_one_in_t  *args_inp,
			       rpc_iter_step_one_out_t *args_outp);

typedef struct {
	dsosd_handle_t	*iter_handles;
	int		op;
	void		**vas;
	size_t		obj_sz;
} rpc_iter_step_all_in_t;
typedef struct {
	int		*found;
} rpc_iter_step_all_out_t;
int	dsos_rpc_iter_step_all(rpc_iter_step_all_in_t  *args_inp,
			       rpc_iter_step_all_out_t *args_outp);

/* Internal API. */
int		dsos_config_read(const char *config_file);
int		dsos_connect(const char *host, const char *service, int server_id);
void		dsos_disconnect(void);
void		dsos_err_clear(void);
void		dsos_err_set(int server_id, int status);
int		*dsos_err_get(void);
int		dsos_err_status(void);
const char	*dsos_msg_type_to_str(int id);
dsos_req_t	*dsos_req_find(dsosd_msg_t *resp);
void		dsos_req_get(dsos_req_t *req);
void		dsos_req_init(void);
dsos_req_t	*dsos_req_new(dsos_req_cb_t cb, void *ctxt);
void		dsos_req_put(dsos_req_t *req);
int		dsos_req_submit(dsos_req_t *req, dsos_conn_t *conn, size_t len);
dsos_req_t	*dsos_req_all_add_server(dsos_req_all_t *req_all, int server_num);
dsos_req_all_t	*dsos_req_all_sparse_new(dsos_req_all_cb_t cb, void *ctxt);
dsos_req_all_t	*dsos_req_all_new(dsos_req_all_cb_t cb, void *ctxt);
void		dsos_req_all_put(dsos_req_all_t *req_all);
int		dsos_req_all_submit(dsos_req_all_t *req_all, size_t len);
void		*dsos_rpc_serialize_schema_template(sos_schema_template_t templ, void *buf,
						    size_t *psz);
sos_schema_template_t dsos_rpc_deserialize_schema_template(char *buf, size_t len);
void		*dsos_rpc_serialize_attr_value(sos_value_t v, void *buf, size_t *psz);

/* Public API. */
int		dsos_container_close(dsos_t *dsos);
dsos_t		*dsos_container_open(const char *path, sos_perm_t perms);
void		dsos_disconnect(void);
int		dsos_init(const char *config_filename);
sos_obj_t	dsos_iter_begin(dsos_iter_t *iter);
int		dsos_iter_close(dsos_iter_t *iter);
dsos_iter_t	*dsos_iter_new(dsos_schema_t *schema, sos_attr_t attr);
sos_obj_t	dsos_iter_next(dsos_iter_t *iter);
dsos_obj_t	*dsos_obj_alloc(dsos_schema_t *schema, dsos_obj_cb_t cb, void *ctxt);
int		dsos_obj_create(dsos_obj_t *obj);
sos_obj_t	dsos_obj_find(dsos_schema_t *schema, sos_attr_t attr, sos_key_t key);
int		dsos_obj_index(dsos_obj_t *obj, dsos_obj_cb_t cb, void *ctxt);
dsos_schema_t	*dsos_schema_by_name(dsos_t *dsos, const char *name);

#define dsos_debug(fmt, ...)	sos_log(SOS_LOG_DEBUG, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define dsos_error(fmt, ...)	sos_log(SOS_LOG_ERROR, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define dsos_fatal(fmt, ...) \
	do {									\
		if (!__ods_log_fp)						\
			__ods_log_fp = stderr;					\
		__ods_log_mask = 0xff;						\
		sos_log(SOS_LOG_FATAL, __func__, __LINE__, fmt, ##__VA_ARGS__);	\
		exit(1);							\
	} while (0);

#endif

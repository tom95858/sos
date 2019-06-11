#ifndef __DSOSD_MSG_LAYOUT_H
#define __DSOSD_MSG_LAYOUT_H

#include "sos_priv.h"

#pragma pack(push,1)

/*
 * A "handle" represents a server-side pointer to something like a container
 * or schema. When we send an RPC to a server, it sends back a handle instead
 * of a pointer. These handles are sent back in operations that locally
 * would take a pointer.
 */
typedef uint64_t	dsosd_handle_t;

/*
 * A DSOS object id is unique within a distributed container. The top
 * uint64_t identifies the server where the object resides, and the
 * bottom uint64_t is the ODS ref which identifies the object within
 * its container on that server. This overlays the original (local) SOS
 * obj id of the same size; it overloads the ODS ref part to store
 * the server ref. The ODS ref is not needed because it is now
 * implied from the container, and from the assumption that the container
 * in DSOS has only one partition.
 */
typedef struct {
	union {
		struct {
			uint64_t	serv;    // owning server
			uint64_t	ods;     // ref inside the ODS
		};
		sos_obj_ref_t	as_obj_ref;
	};
} dsosd_objid_t;

#define DSOSD_MSG_MAX_PATH	128   // len of fixed-size char arrays in msgs
#define DSOSD_MSG_MAX_DATA	1900  // conservative len of in-line data array

/* Message types. */
enum {
	DSOSD_MSG_INVALID = 0,        // indicates no msg for a server in a vector RPC
	DSOSD_MSG_PING_REQ,
	DSOSD_MSG_PING_RESP,
	DSOSD_MSG_OBJ_CREATE_REQ,
	DSOSD_MSG_OBJ_CREATE_RESP,
	DSOSD_MSG_OBJ_INDEX_REQ,
	DSOSD_MSG_OBJ_INDEX_RESP,
	DSOSD_MSG_OBJ_FIND_REQ,
	DSOSD_MSG_OBJ_FIND_RESP,
	DSOSD_MSG_OBJ_GET_REQ,
	DSOSD_MSG_OBJ_GET_RESP,
	DSOSD_MSG_CONTAINER_NEW_REQ,
	DSOSD_MSG_CONTAINER_NEW_RESP,
	DSOSD_MSG_CONTAINER_OPEN_REQ,
	DSOSD_MSG_CONTAINER_OPEN_RESP,
	DSOSD_MSG_CONTAINER_DELETE_REQ,
	DSOSD_MSG_CONTAINER_DELETE_RESP,
	DSOSD_MSG_CONTAINER_CLOSE_REQ,
	DSOSD_MSG_CONTAINER_CLOSE_RESP,
	DSOSD_MSG_ITERATOR_CLOSE_REQ,
	DSOSD_MSG_ITERATOR_CLOSE_RESP,
	DSOSD_MSG_ITERATOR_NEW_REQ,
	DSOSD_MSG_ITERATOR_NEW_RESP,
	DSOSD_MSG_ITERATOR_STEP_REQ,
	DSOSD_MSG_ITERATOR_STEP_RESP,
	DSOSD_MSG_PART_CREATE_REQ,
	DSOSD_MSG_PART_CREATE_RESP,
	DSOSD_MSG_PART_FIND_REQ,
	DSOSD_MSG_PART_FIND_RESP,
	DSOSD_MSG_PART_SET_STATE_REQ,
	DSOSD_MSG_PART_SET_STATE_RESP,
	DSOSD_MSG_SCHEMA_FROM_TEMPLATE_REQ,
	DSOSD_MSG_SCHEMA_FROM_TEMPLATE_RESP,
	DSOSD_MSG_SCHEMA_ADD_REQ,
	DSOSD_MSG_SCHEMA_ADD_RESP,
	DSOSD_MSG_SCHEMA_BY_NAME_REQ,
	DSOSD_MSG_SCHEMA_BY_NAME_RESP,
};

/* Message flags. */
enum {
	DSOSD_MSG_IMM  = 0x00000001,
};

/*
 * A message can be referenced as one of the unions in dsosd_msg_t
 * or by casting to one of the message types below. Sometimes one
 * method is more convenient.
 */

typedef struct dsosd_msg_hdr {
	uint64_t	id;         // unique id for the request/response
	uint16_t	type;       // message type enum
	uint16_t	status;
	uint32_t	flags;
} dsosd_msg_hdr_t;

// This is in messages that move SOS objects between client and server.
typedef struct dsosd_msg_hdr2 {
	uint64_t	obj_sz;
	uint64_t	obj_va;
} dsosd_msg_hdr2_t;

typedef struct dsosd_msg_ping_req {
	dsosd_msg_hdr_t		hdr;
	uint32_t		dump;
} dsosd_msg_ping_req_t;

typedef struct dsosd_msg_ping_resp {
	dsosd_msg_hdr_t		hdr;
	uint32_t		tot_num_connects;
	uint32_t		tot_num_disconnects;
	uint32_t		tot_num_reqs;
	uint32_t		num_clients;
	char			data[];
} dsosd_msg_ping_resp_t;

typedef struct dsosd_msg_container_new_req {
	dsosd_msg_hdr_t		hdr;
	char			path[DSOSD_MSG_MAX_PATH];
	uint32_t		mode;
} dsosd_msg_container_new_req_t;

typedef struct dsosd_msg_container_new_resp {
	dsosd_msg_hdr_t		hdr;
} dsosd_msg_container_new_resp_t;

typedef struct dsosd_msg_container_open_req {
	dsosd_msg_hdr_t		hdr;
	char			path[DSOSD_MSG_MAX_PATH];
	uint32_t		perms;
} dsosd_msg_container_open_req_t;

typedef struct dsosd_msg_container_open_resp {
	dsosd_msg_hdr_t		hdr;
	dsosd_handle_t		handle;
} dsosd_msg_container_open_resp_t;

typedef struct dsosd_msg_container_delete_req {
	dsosd_msg_hdr_t		hdr;
	char			path[DSOSD_MSG_MAX_PATH];
} dsosd_msg_container_delete_req_t;

typedef struct dsosd_msg_container_delete_resp {
	dsosd_msg_hdr_t		hdr;
} dsosd_msg_container_delete_resp_t;

typedef struct dsosd_msg_container_close_req {
	dsosd_msg_hdr_t		hdr;
	dsosd_handle_t		handle;
} dsosd_msg_container_close_req_t;

typedef struct dsosd_msg_container_close_resp {
	dsosd_msg_hdr_t		hdr;
} dsosd_msg_container_close_resp_t;

typedef struct dsosd_msg_part_create_req {
	dsosd_msg_hdr_t		hdr;
	dsosd_handle_t		cont_handle;
	char			name[DSOSD_MSG_MAX_PATH];
	char			path[DSOSD_MSG_MAX_PATH];
} dsosd_msg_part_create_req_t;

typedef struct dsosd_msg_part_create_resp {
	dsosd_msg_hdr_t		hdr;
} dsosd_msg_part_create_resp_t;

typedef struct dsosd_msg_part_find_req {
	dsosd_msg_hdr_t		hdr;
	dsosd_handle_t		cont_handle;
	char			name[DSOSD_MSG_MAX_PATH];
} dsosd_msg_part_find_req_t;

typedef struct dsosd_msg_part_find_resp {
	dsosd_msg_hdr_t		hdr;
	dsosd_handle_t		handle;
} dsosd_msg_part_find_resp_t;

typedef struct dsosd_msg_part_set_state_req {
	dsosd_msg_hdr_t		hdr;
	dsosd_handle_t		handle;
	int			new_state;
} dsosd_msg_part_set_state_req_t;

typedef struct dsosd_msg_part_set_state_resp {
	dsosd_msg_hdr_t		hdr;
} dsosd_msg_part_set_state_resp_t;

typedef struct dsosd_msg_schema_from_template_req {
	dsosd_msg_hdr_t		hdr;
	char			templ[DSOSD_MSG_MAX_DATA];
} dsosd_msg_schema_from_template_req_t;

typedef struct dsosd_msg_schema_from_template_resp {
	dsosd_msg_hdr_t		hdr;
	dsosd_handle_t		handle;
} dsosd_msg_schema_from_template_resp_t;

typedef struct dsosd_msg_schema_add_req {
	dsosd_msg_hdr_t		hdr;
	dsosd_handle_t		cont_handle;
	dsosd_handle_t		schema_handle;
} dsosd_msg_schema_add_req_t;

typedef struct dsosd_msg_schema_add_resp {
	dsosd_msg_hdr_t		hdr;
} dsosd_msg_schema_add_resp_t;

typedef struct dsosd_msg_schema_by_name_req {
	dsosd_msg_hdr_t		hdr;
	dsosd_handle_t		cont_handle;
	char			name[DSOSD_MSG_MAX_PATH];
} dsosd_msg_schema_by_name_req_t;

typedef struct dsosd_msg_schema_by_name_resp {
	dsosd_msg_hdr_t		hdr;
	dsosd_handle_t		handle;
	char			templ[DSOSD_MSG_MAX_DATA];
} dsosd_msg_schema_by_name_resp_t;

typedef struct dsosd_msg_obj_create_req {
	dsosd_msg_hdr_t		hdr;
	dsosd_msg_hdr2_t	hdr2;
	dsosd_handle_t		schema_handle;
	char			data[];
} dsosd_msg_obj_create_req_t;

typedef struct dsosd_msg_obj_create_resp {
	dsosd_msg_hdr_t		hdr;
	uint64_t		len;
	dsosd_objid_t		obj_id;
} dsosd_msg_obj_create_resp_t;

typedef struct dsosd_msg_obj_index_req {
	dsosd_msg_hdr_t		hdr;
	dsosd_handle_t		cont_handle;
	dsosd_handle_t		schema_handle;
	dsosd_objid_t		obj_id;
	uint16_t		num_attrs;
	uint16_t		data_len;
	char			data[];
} dsosd_msg_obj_index_req_t;

typedef struct dsosd_msg_obj_index_resp {
	dsosd_msg_hdr_t		hdr;
} dsosd_msg_obj_index_resp_t;

typedef struct dsosd_msg_obj_find_req {
	dsosd_msg_hdr_t		hdr;
	dsosd_msg_hdr2_t	hdr2;
	dsosd_handle_t		cont_handle;
	dsosd_handle_t		schema_handle;
	uint32_t		attr_id;
	uint32_t		data_len;
	char			data[];
} dsosd_msg_obj_find_req_t;

typedef struct dsosd_msg_obj_find_resp {
	dsosd_msg_hdr_t		hdr;
	dsosd_msg_hdr2_t	hdr2;
	dsosd_objid_t		obj_id;
	char			data[];
} dsosd_msg_obj_find_resp_t;

typedef struct dsosd_msg_obj_get_req {
	dsosd_msg_hdr_t		hdr;
	dsosd_msg_hdr2_t	hdr2;
	dsosd_handle_t		cont_handle;
	dsosd_objid_t		obj_id;
} dsosd_msg_obj_get_req_t;

typedef struct dsosd_msg_obj_get_resp {
	dsosd_msg_hdr_t		hdr;
	dsosd_msg_hdr2_t	hdr2;
	char			data[];
} dsosd_msg_obj_get_resp_t;

typedef struct dsosd_msg_iterator_new_req {
	dsosd_msg_hdr_t		hdr;
	dsosd_handle_t		cont_handle;
	dsosd_handle_t		schema_handle;
	uint32_t		attr_id;
} dsosd_msg_iterator_new_req_t;

typedef struct dsosd_msg_iterator_new_resp {
	dsosd_msg_hdr_t		hdr;
	dsosd_handle_t		iter_handle;
} dsosd_msg_iterator_new_resp_t;

typedef struct dsosd_msg_iterator_close_req {
	dsosd_msg_hdr_t		hdr;
	dsosd_handle_t		iter_handle;
} dsosd_msg_iterator_close_req_t;

typedef struct dsosd_msg_iterator_close_resp {
	dsosd_msg_hdr_t		hdr;
} dsosd_msg_iterator_close_resp_t;

enum {
	DSOSD_MSG_ITER_OP_NONE = 0x00000001,
	DSOSD_MSG_ITER_OP_FIND,
	DSOSD_MSG_ITER_OP_BEGIN,
	DSOSD_MSG_ITER_OP_END,
	DSOSD_MSG_ITER_OP_NEXT,
	DSOSD_MSG_ITER_OP_PREV,
};

typedef struct dsosd_msg_iterator_step_req {
	dsosd_msg_hdr_t		hdr;
	dsosd_msg_hdr2_t	hdr2;
	dsosd_handle_t		iter_handle;
	uint32_t		op;
	uint32_t		data_len;
	char			data[];
} dsosd_msg_iterator_step_req_t;

typedef struct dsosd_msg_iterator_step_resp {
	dsosd_msg_hdr_t		hdr;
	dsosd_msg_hdr2_t	hdr2;
	char			data[];
} dsosd_msg_iterator_step_resp_t;

typedef struct dsosd_msg {
	union {
		struct {
			dsosd_msg_hdr_t			hdr;
			dsosd_msg_hdr2_t		hdr2;
		};
		dsosd_msg_container_close_req_t		container_close_req;
		dsosd_msg_container_close_resp_t	container_close_resp;
		dsosd_msg_container_new_req_t		container_new_req;
		dsosd_msg_container_new_resp_t		container_new_resp;
		dsosd_msg_container_delete_req_t	container_delete_req;
		dsosd_msg_container_delete_resp_t	container_delete_resp;
		dsosd_msg_container_open_req_t		container_open_req;
		dsosd_msg_container_open_resp_t		container_open_resp;
		dsosd_msg_iterator_close_req_t		iterator_close_req;
		dsosd_msg_iterator_close_resp_t		iterator_close_resp;
		dsosd_msg_iterator_new_req_t		iterator_new_req;
		dsosd_msg_iterator_new_resp_t		iterator_new_resp;
		dsosd_msg_iterator_step_req_t		iterator_step_req;
		dsosd_msg_iterator_step_resp_t		iterator_step_resp;
		dsosd_msg_obj_create_req_t		obj_create_req;
		dsosd_msg_obj_create_resp_t		obj_create_resp;
		dsosd_msg_obj_find_req_t		obj_find_req;
		dsosd_msg_obj_find_resp_t		obj_find_resp;
		dsosd_msg_obj_get_req_t			obj_get_req;
		dsosd_msg_obj_get_resp_t		obj_get_resp;
		dsosd_msg_obj_index_req_t		obj_index_req;
		dsosd_msg_obj_index_resp_t		obj_index_resp;
		dsosd_msg_part_create_req_t		part_create_req;
		dsosd_msg_part_create_resp_t		part_create_resp;
		dsosd_msg_part_find_req_t		part_find_req;
		dsosd_msg_part_find_resp_t		part_find_resp;
		dsosd_msg_part_set_state_req_t		part_set_state_req;
		dsosd_msg_part_set_state_resp_t		part_set_state_resp;
		dsosd_msg_ping_req_t			ping_req;
		dsosd_msg_ping_resp_t			ping_resp;
		dsosd_msg_schema_add_req_t		schema_add_req;
		dsosd_msg_schema_add_resp_t		schema_add_resp;
		dsosd_msg_schema_by_name_req_t		schema_by_name_req;
		dsosd_msg_schema_by_name_resp_t		schema_by_name_resp;
		dsosd_msg_schema_from_template_req_t	schema_from_template_req;
		dsosd_msg_schema_from_template_resp_t	schema_from_template_resp;
	} u;
} dsosd_msg_t;

#pragma pack(pop)

#endif
#ifndef __DSOSD_MSG_LAYOUT_H
#define __DSOSD_MSG_LAYOUT_H

/*
 * A "handle" represents a server-side pointer to something like a container
 * or schema. When we send an RPC to a server, it sends back a handle instead
 * of a pointer. These handles are sent back in operations that locally
 * would take a pointer.
 */
typedef uint64_t	dsosd_handle_t;

#define DSOSD_MSG_MAX_PATH	128   // len of fixed-size char arrays in msgs
#define DSOSD_MSG_MAX_DATA	1900  // conservative len of in-line data array

enum {
	DSOSD_MSG_PING_REQ = 1999,  // 1999 is arbitrary but recognizable while debugging
	DSOSD_MSG_PING_RESP,
	DSOSD_MSG_OBJ_CREATE_REQ,
	DSOSD_MSG_OBJ_CREATE_RESP,
	DSOSD_MSG_CONTAINER_NEW_REQ,
	DSOSD_MSG_CONTAINER_NEW_RESP,
	DSOSD_MSG_CONTAINER_OPEN_REQ,
	DSOSD_MSG_CONTAINER_OPEN_RESP,
	DSOSD_MSG_CONTAINER_CLOSE_REQ,
	DSOSD_MSG_CONTAINER_CLOSE_RESP,
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

enum {
	DSOSD_MSG_IMM  = 0x00000001,
};

#pragma pack(push,1)

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

typedef struct dsosd_msg_ping_req {
	dsosd_msg_hdr_t		hdr;
	char			data[];
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
	char			template[DSOSD_MSG_MAX_DATA];
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
	char			template[DSOSD_MSG_MAX_DATA];
} dsosd_msg_schema_by_name_resp_t;

typedef struct dsosd_msg_obj_create_req {
	dsosd_msg_hdr_t		hdr;
	dsosd_handle_t		schema_handle;
	uint64_t		len;
	uint64_t		va;
	char			data[];
} dsosd_msg_obj_create_req_t;

typedef struct dsosd_msg_obj_create_resp {
	dsosd_msg_hdr_t		hdr;
	uint64_t		len;
	uint64_t		obj_id;
} dsosd_msg_obj_create_resp_t;

typedef struct dsosd_msg {
	union {
		dsosd_msg_hdr_t				hdr;
		dsosd_msg_ping_req_t			ping_req;
		dsosd_msg_ping_resp_t			ping_resp;
		dsosd_msg_container_new_req_t		container_new_req;
		dsosd_msg_container_new_resp_t		container_new_resp;
		dsosd_msg_container_open_req_t		container_open_req;
		dsosd_msg_container_open_resp_t		container_open_resp;
		dsosd_msg_container_close_req_t		container_close_req;
		dsosd_msg_container_close_resp_t	container_close_resp;
		dsosd_msg_part_create_req_t		part_create_req;
		dsosd_msg_part_create_resp_t		part_create_resp;
		dsosd_msg_part_find_req_t		part_find_req;
		dsosd_msg_part_find_resp_t		part_find_resp;
		dsosd_msg_part_set_state_req_t		part_set_state_req;
		dsosd_msg_part_set_state_resp_t		part_set_state_resp;
		dsosd_msg_schema_from_template_req_t	schema_from_template_req;
		dsosd_msg_schema_from_template_resp_t	schema_from_template_resp;
		dsosd_msg_schema_add_req_t		schema_add_req;
		dsosd_msg_schema_add_resp_t		schema_add_resp;
		dsosd_msg_schema_by_name_req_t		schema_by_name_req;
		dsosd_msg_schema_by_name_resp_t		schema_by_name_resp;
		dsosd_msg_obj_create_req_t		obj_create_req;
		dsosd_msg_obj_create_resp_t		obj_create_resp;
	} u;
} dsosd_msg_t;

#pragma pack(pop)

#endif

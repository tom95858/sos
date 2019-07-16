#ifndef __DSOSD_RPC_MSG_H
#define __DSOSD_RPC_MSG_H

/* RPC message types. */

typedef enum {
	DSOS_RPC_INVALID = 0,
	DSOS_RPC_CONT_CLOSE,
	DSOS_RPC_CONT_NEW,
	DSOS_RPC_CONT_OPEN,
	DSOS_RPC_ITER_CLOSE,
	DSOS_RPC_ITER_NEW,
	DSOS_RPC_ITER_STEP,
	DSOS_RPC_OBJ_CREATE,
	DSOS_RPC_OBJ_DELETE,
	DSOS_RPC_OBJ_GET,
	DSOS_RPC_PART_CREATE,
	DSOS_RPC_PART_FIND,
	DSOS_RPC_PART_SET_STATE,
	DSOS_RPC_PING,
	DSOS_RPC_SCHEMA_ADD,
	DSOS_RPC_SCHEMA_BY_NAME,
	DSOS_RPC_SCHEMA_FROM_TEMPLATE,
} dsos_rpc_type_t;

/* RPC flags. */

typedef enum {
	DSOS_RPC_FLAGS_INLINE	= 0x00000001,
} dsos_msg_flags_t;

enum {
	DSOS_RPC_ITER_OP_NONE	= 0x00000001,
	DSOS_RPC_ITER_OP_BEGIN,
	DSOS_RPC_ITER_OP_END,
	DSOS_RPC_ITER_OP_NEXT,
	DSOS_RPC_ITER_OP_FIND,
};

#pragma pack(push,1)

typedef struct dsos_msg_hdr {
	uint64_t	id;         // unique id for the request/response
	uint16_t	type;
	uint16_t	status;
	uint32_t	flags;
} dsos_msg_hdr_t;

typedef struct dsos_msg_s {
	dsos_msg_hdr_t	hdr;
} dsos_msg_t;

#pragma pack(pop)

#endif

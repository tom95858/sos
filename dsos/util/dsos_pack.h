#ifndef __DSOS_PACK_H
#define __DSOS_PACK_H

#include <stddef.h>
#include <stdint.h>
#include <sos/sos.h>
#include "../server/dsos_rpc_msg.h"

typedef struct dsos_buf_s	dsos_buf_t;

typedef struct dsos_buf_s {
	dsos_msg_t		*msg;                      // the formatted msg
	size_t			allocated;                 // # bytes allocated for msg
	size_t			len;                       // # bytes used so far
	void			(*free_fn)(void *ptr);     // called to free msg
	char			*p;                        // pack/unpack cursor
} dsos_buf_t;

int		dsos_pack_buf(dsos_buf_t *buf, void *ptr, int len);
int		dsos_pack_fits(dsos_buf_t *buf, int len);
int		dsos_pack_key(dsos_buf_t *buf, sos_key_t key);
int		dsos_pack_obj(dsos_buf_t *buf, sos_obj_t obj);
int		dsos_pack_obj_id(dsos_buf_t *buf, sos_obj_ref_t obj_id);
int		dsos_pack_obj_needs(sos_obj_t obj);
int		dsos_pack_obj_ptr(dsos_buf_t *buf, sos_obj_t obj);
int		dsos_pack_schema(dsos_buf_t *buf, sos_schema_t schema);
int		dsos_pack_str(dsos_buf_t *buf, const char *str);
int		dsos_pack_u32(dsos_buf_t *buf, uint32_t val);
int		dsos_pack_u64(dsos_buf_t *buf, uint64_t val);

void		dsos_buf_dump(FILE *f, dsos_buf_t *buf, const char *str);
const char	*dsos_rpc_type_to_str(int type);

void		*dsos_unpack_buf(dsos_buf_t *buf, int *plen);
sos_key_t	dsos_unpack_key(dsos_buf_t *buf);
int		dsos_unpack_obj(dsos_buf_t *buf, sos_obj_t obj);
sos_obj_ref_t	dsos_unpack_obj_id(dsos_buf_t *buf);
uint64_t	dsos_unpack_obj_ptr(dsos_buf_t *buf, uint64_t *plen);
sos_schema_t	dsos_unpack_schema(dsos_buf_t *buf);
char		*dsos_unpack_str(dsos_buf_t *buf);
uint32_t	dsos_unpack_u32(dsos_buf_t *buf);
uint64_t	dsos_unpack_u64(dsos_buf_t *buf);


#endif

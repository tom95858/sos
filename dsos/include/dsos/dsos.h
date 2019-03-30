#ifndef __DSOS_H
#define __DSOS_H

#include <sos/sos.h>

typedef struct dsos_s		dsos_t;
typedef struct dsos_part_s	dsos_part_t;
typedef struct dsos_schema_s	dsos_schema_t;
typedef struct dsos_obj_s	dsos_obj_t;
typedef void (*dsos_obj_cb_t)(dsos_obj_t *, void *);

int		dsos_container_close(dsos_t *dsos);
dsos_t		*dsos_container_open(const char *path, sos_perm_t perms);
int		dsos_container_new(const char *path, int mode);
void		dsos_disconnect(void);
int		*dsos_err_get(void);
int		dsos_init(const char *config_filename);
dsos_obj_t	*dsos_obj_alloc(size_t sz, dsos_obj_cb_t cb, void *ctxt);
int		dsos_obj_create(dsos_obj_t *obj, dsos_schema_t *schema, size_t len);
int		dsos_part_create(dsos_t *cont, const char *part_name, const char *part_path);
dsos_part_t	*dsos_part_find(dsos_t *cont, const char *name);
int		dsos_part_state_set(dsos_part_t *part, sos_part_state_t new_state);
int		dsos_schema_add(dsos_t *cont, dsos_schema_t *schema);
dsos_schema_t	*dsos_schema_from_template(sos_schema_template_t t);
dsos_schema_t	*dsos_schema_by_name(dsos_t *dsos, const char *name);

#endif

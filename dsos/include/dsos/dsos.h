#ifndef __DSOS_H
#define __DSOS_H

#include <sos/sos.h>

typedef struct dsos_s		dsos_t;
typedef struct dsos_part_s	dsos_part_t;
typedef struct dsos_schema_s	dsos_schema_t;
typedef struct dsos_iter_s	dsos_iter_t;
typedef void (*dsos_obj_cb_t)(sos_obj_t, void *);

struct dsos_ping_stats {
	int		tot_num_connects;
	int		tot_num_disconnects;
	int		tot_num_reqs;
	int		num_clients;
	uint64_t	nsecs;
};

enum {
	DSOS_ERR_LOCAL  = 1,
	DSOS_ERR_REMOTE = 2
};
typedef struct dsos_err_s {
	int	*local;          // vector of local statuses, one per server
	int	*remote;         // vector of remote statuses, one per server
} dsos_err_t;

/*
 * DSOS version of errno. This is a thread-local vector of
 * g.num_servers statuses of both of the local and remote operations
 * performed for the most recent DSOS API call.
 */
extern __thread dsos_err_t	dsos_errno;

int		dsos_container_close(dsos_t *dsos);
dsos_t		*dsos_container_open(const char *path, sos_perm_t perms);
int		dsos_container_new(const char *path, int mode);
void		dsos_disconnect(void);
void		dsos_err_clear(dsos_err_t err);
void		dsos_err_free(dsos_err_t err);
int		dsos_err_get_local(dsos_err_t err, int server_num);
int		dsos_err_get_remote(dsos_err_t err, int server_num);
dsos_err_t	dsos_err_new(void);
int		dsos_err_set(dsos_err_t to, dsos_err_t from);
void		dsos_err_set_local_all(dsos_err_t to, int status);
void		dsos_err_set_local(dsos_err_t err, int server_num, int status);
void		dsos_err_set_remote(dsos_err_t err, int server_num, int status);
int		dsos_err_status(dsos_err_t err);
int		dsos_init(const char *config_filename);
sos_obj_t	dsos_iter_begin(dsos_iter_t *iter);
int		dsos_iter_close(dsos_iter_t *iter);
sos_obj_t	dsos_iter_find(dsos_iter_t *iter, sos_key_t key);
dsos_iter_t	*dsos_iter_new(dsos_schema_t *schema, sos_attr_t attr);
sos_obj_t	dsos_iter_next(dsos_iter_t *iter);
sos_obj_t	dsos_obj_alloc(dsos_schema_t *schema);
int		dsos_obj_create(sos_obj_t obj, dsos_obj_cb_t cb, void *ctxt);
sos_obj_t	dsos_obj_get(dsos_schema_t *schema, sos_obj_ref_t obj_id);
int		dsos_obj_delete(sos_obj_t obj);
int		dsos_part_create(dsos_t *cont, const char *part_name, const char *part_path);
dsos_part_t	*dsos_part_find(dsos_t *cont, const char *name);
int		dsos_part_state_set(dsos_part_t *part, sos_part_state_t new_state);
void		dsos_perror(const char *fmt, ...);
int		dsos_ping_one(int server_num, struct dsos_ping_stats *stats);
int		dsos_ping_all(struct dsos_ping_stats **statsp, int dump);
int		dsos_schema_add(dsos_t *cont, dsos_schema_t *schema);
dsos_schema_t	*dsos_schema_from_template(sos_schema_template_t t);
dsos_schema_t	*dsos_schema_by_name(dsos_t *dsos, const char *name);

#endif

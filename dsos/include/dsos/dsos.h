#ifndef __DSOS_H
#define __DSOS_H

#include <sos/sos.h>

typedef struct dsos_s		dsos_t;
typedef struct dsos_part_s	dsos_part_t;
typedef struct dsos_schema_s	dsos_schema_t;
typedef struct dsos_iter_s	dsos_iter_t;
typedef struct dsos_index_s	dsos_index_t;
typedef struct dsos_filter_s	dsos_filter_t;
typedef struct dsos_part_iter_s	dsos_part_iter_t;
typedef struct dsos_container_index_iter_s	dsos_container_index_iter_t;
typedef void (*dsos_obj_cb_t)(sos_obj_t, void *);

struct dsos_ping_stats {
	int		tot_num_connects;
	int		tot_num_disconnects;
	int		tot_num_reqs;
	int		tot_num_obj_creates_rma;
	int		tot_num_obj_creates_inline;
	int		tot_num_obj_gets_rma;
	int		tot_num_obj_gets_inline;
	int		num_clients;
	uint64_t	nsecs;
};

/*
 * A "handle" represents a server-side pointer to something like a container
 * or schema. When we send an RPC to a server, it sends back a handle instead
 * of a pointer. These handles are sent back in operations that locally
 * would take a pointer.
 */
typedef uint64_t	dsos_handle_t;

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
 * g.num_servers statuses of both the local and remote operations
 * performed for the most recent DSOS API call.
 */
extern __thread dsos_err_t	dsos_errno;

int		dsos_attr_is_indexed(sos_attr_t attr);
dsos_index_t	*dsos_attr_index(sos_attr_t attr);
dsos_iter_t	*dsos_attr_iter_new(sos_attr_t attr);
void		dsos_container_close(dsos_t *cont, int commit);
int		dsos_container_commit(dsos_t *cont, int commit);
dsos_t		*dsos_container_open(const char *path, sos_perm_t perms);
int		dsos_container_new(const char *path, int mode);
int		dsos_container_version(dsos_t *cont);
dsos_container_index_iter_t *dsos_container_index_iter_new(dsos_t *cont);
dsos_index_t	*dsos_container_index_iter_first(dsos_container_index_iter_t *cont_iter);
dsos_index_t	*dsos_container_index_iter_next(dsos_container_index_iter_t *cont_iter);
void		dsos_container_index_iter_free(dsos_container_index_iter_t *cont_iter);
void		dsos_disconnect();
void		dsos_err_clear(dsos_err_t err);
void		dsos_err_free(dsos_err_t err);
int		dsos_err_get_local(dsos_err_t err, int server_num);
int		dsos_err_get_remote(dsos_err_t err, int server_num);
dsos_err_t	dsos_err_new();
int		dsos_err_set(dsos_err_t err_to, dsos_err_t err_from);
void		dsos_err_set_local_all(dsos_err_t err_to, int status);
void		dsos_err_set_local(dsos_err_t err, int server_num, int status);
void		dsos_err_set_remote(dsos_err_t err, int server_num, int status);
int		dsos_err_status(dsos_err_t err);
int		dsos_filter_cond_add(dsos_filter_t *f, sos_attr_t attr,
				     enum sos_cond_e cond_e, sos_value_t value);
dsos_filter_t	*dsos_filter_new(dsos_iter_t *iter);
sos_iter_flags_t dsos_filter_flags_get(dsos_filter_t *filter);
void		dsos_filter_flags_set(dsos_filter_t *filter, sos_iter_flags_t flags);
sos_obj_t	dsos_filter_begin(dsos_filter_t *filter);
sos_obj_t	dsos_filter_end(dsos_filter_t *filter);
sos_obj_t	dsos_filter_next(dsos_filter_t *filter);
int		dsos_filter_pos_get(dsos_filter_t *filter, sos_pos_t *pos);
int		dsos_filter_pos_put(dsos_filter_t *filter, sos_pos_t pos);
int		dsos_filter_pos_set(dsos_filter_t *filter, sos_pos_t pos);
sos_obj_t	dsos_filter_prev(dsos_filter_t *filter);
int		dsos_filter_miss_count(dsos_filter_t *filter);
sos_obj_t	dsos_filter_obj(dsos_filter_t *filter);
int		dsos_filter_pos_get(dsos_filter_t *filter, sos_pos_t *pos);
void		dsos_filter_free(dsos_filter_t *filter);
int		dsos_index_new(dsos_t *cont, const char *name, const char *idx_type,
			       sos_type_t key_type, const char *args);
dsos_index_t	*dsos_index_open(dsos_t *cont, const char *name);
int		dsos_index_insert(dsos_index_t *index, sos_key_t key, sos_obj_t obj);
int		dsos_index_remove(dsos_index_t *index, sos_key_t key, sos_obj_t obj);
int		dsos_index_insert_ref(dsos_index_t *index, sos_key_t key, sos_obj_ref_t ref);
int		dsos_index_remove_ref(dsos_index_t *index, sos_key_t key, sos_obj_ref_t *ref);
sos_obj_t	dsos_index_find(dsos_index_t *index, sos_key_t key);
int		dsos_index_find_ref(dsos_index_t *index, sos_key_t key, sos_obj_ref_t *ref);
sos_obj_t	dsos_index_find_inf(dsos_index_t *index, sos_key_t key);
sos_obj_t	dsos_index_find_sup(dsos_index_t *index, sos_key_t key);
sos_obj_t	dsos_index_find_min(dsos_index_t *index, sos_key_t *key);
sos_obj_t	dsos_index_find_max(dsos_index_t *index, sos_key_t *key);
int		dsos_index_find_min_ref(dsos_index_t *index, sos_key_t *key, sos_obj_ref_t *ref);
int		dsos_index_find_max_ref(dsos_index_t *index, sos_key_t *key, sos_obj_ref_t *ref);
sos_type_t	dsos_index_key_type(dsos_index_t *index);
const char	*dsos_index_name(dsos_index_t *index);
void		dsos_index_print(dsos_index_t *index, FILE *f);
int		dsos_index_stat(dsos_index_t *index, sos_index_stat_t stats);
int		dsos_init(const char *config_filename);
int		dsos_iter_begin(dsos_iter_t *iter);
int		dsos_iter_end(dsos_iter_t *iter);
int		dsos_iter_find(dsos_iter_t *iter, sos_key_t key);
int		dsos_iter_find_sup(dsos_iter_t *iter, sos_key_t key);
int		dsos_iter_find_inf(dsos_iter_t *iter, sos_key_t key);
void		dsos_iter_free(dsos_iter_t *iter);
sos_key_t	dsos_iter_key(dsos_iter_t *iter);
sos_iter_flags_t dsos_iter_flags_get(dsos_iter_t *iter);
void		dsos_iter_flags_set(dsos_iter_t *iter, sos_iter_flags_t flags);
int		dsos_iter_next(dsos_iter_t *iter);
sos_obj_t	dsos_iter_obj(dsos_iter_t *iter);
int		dsos_iter_pos_get(dsos_iter_t *iter, sos_pos_t *pos);
int		dsos_iter_pos_put(dsos_iter_t *iter, sos_pos_t pos);
int		dsos_iter_pos_set(dsos_iter_t *iter, sos_pos_t pos);
int		dsos_iter_prev(dsos_iter_t *iter);
sos_obj_t	dsos_obj_alloc(sos_schema_t schema);
int		dsos_obj_create(sos_obj_t obj, dsos_obj_cb_t cb, void *ctxt);
sos_obj_t	dsos_obj_get(sos_schema_t schema, sos_obj_ref_t obj_id);
int		dsos_obj_delete(sos_obj_t obj);
int		dsos_obj_index(sos_obj_t obj);
int		dsos_obj_remove(sos_obj_t obj);
int		dsos_part_create(dsos_t *cont, const char *part_name, const char *part_path);
int		dsos_part_id(dsos_part_t *part);
char		*dsos_part_name(dsos_part_t *part);
char		*dsos_part_path(dsos_part_t *part);
int		dsos_part_delete(dsos_part_t *part);
int		dsos_part_move(dsos_part_t *part, const char *new_path);
int		dsos_part_export(dsos_part_t *part, dsos_t *dst_cont, int reindex);
int		dsos_part_index(dsos_part_t *part);
void		dsos_part_put(dsos_part_t *part);
dsos_part_t	*dsos_part_find(dsos_t *cont, const char *name);
dsos_part_iter_t *dsos_part_iter_new(dsos_t *cont);
dsos_part_t	*dsos_part_first(dsos_part_iter_t *part_iter);
dsos_part_t	*dsos_part_next(dsos_part_iter_t *part_iter);
void		dsos_part_iter_free(dsos_part_iter_t *part_iter);
int		dsos_part_state_set(dsos_part_t *part, sos_part_state_t new_state);
void		dsos_perror(const char *fmt, ...);
char		*dsos_pos_to_str(sos_pos_t pos);
int		dsos_pos_from_str(sos_pos_t *pos, const char *str);
int		dsos_schema_add(dsos_t *cont, sos_schema_t schema);
sos_schema_t	dsos_schema_by_name(dsos_t *cont, const char *name);
sos_schema_t	dsos_schema_by_id(dsos_t *cont, int id);
sos_schema_t	dsos_schema_first(dsos_t *cont);
sos_schema_t	dsos_schema_next(sos_schema_t schema);

#endif

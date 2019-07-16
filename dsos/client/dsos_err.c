/*
 * A dsos_err_t encapsulates two status vectors, one for local status
 * and one for remote. Local status comes from immediate failures of
 * operations like zap_send. Remote status comes via server response
 * messages and is stored in the response-message header. This API
 * helps to collect both statuses during a DSOS API.
 *
 * The thread-local global variable dsos_errno is used much like
 * libc's errno. Because it is thread-local storage, care must be
 * taken to set it on the proper thread. To aid with this, DSOS
 * requests contain a dsos_err_t which is used to collect status
 * for that request and is copied to dsos_errno just before the
 * DSOS API returns to the caller (see dsos_req.c).
 *
 * Since dsos_errno contains two vectors, call dsos_err_status()
 * to determine whether there is a local or remote error (non-0 status).
 * This call returns the bits DSOS_ERR_LOCAL and/or DSOS_ERR_REMOTE.
 */

#include "dsos_priv.h"

dsos_err_t dsos_err_new(void)
{
	int		*p;
	dsos_err_t	err;

	p = (int *)malloc(g.num_servers * 2 * sizeof(int));
	if (!p)
		dsos_fatal("out of memory\n");
	err.local  = p;
	err.remote = p + g.num_servers;
	dsos_err_clear(err);
	return err;
}

void dsos_err_clear(dsos_err_t err)
{
	bzero(err.local, g.num_servers * 2 * sizeof(int));
}

int dsos_err_set(dsos_err_t to, dsos_err_t from)
{
	dsos_err_free(to);
	to = from;
	return dsos_err_status(to);
}

void dsos_err_set_local(dsos_err_t err, int server_num, int status)
{
	err.local[server_num] = status;
}

void dsos_err_set_remote(dsos_err_t err, int server_num, int status)
{
	err.remote[server_num] = status;
}

void dsos_err_set_local_all(dsos_err_t err, int status)
{
	int	i;

	for (i = 0; i < g.num_servers; ++i)
		dsos_err_set_local(err, i, status);
}

int dsos_err_get_local(dsos_err_t err, int server_num)
{
	if (err.local)
		return err.local[server_num];
	return -1;
}

int dsos_err_get_remote(dsos_err_t err, int server_num)
{
	if (err.remote)
		return err.remote[server_num];
	return -1;
}

int dsos_err_status(dsos_err_t err)
{
	int	i, ret = 0;

	for (i = 0; i < g.num_servers; ++i) {
		if (err.local[i])
			ret |= DSOS_ERR_LOCAL;
		if (err.remote[i])
			ret |= DSOS_ERR_REMOTE;
	}
	return ret;
}

void dsos_err_free(dsos_err_t err)
{
	if (err.local)
		free(err.local);
	err.local = err.remote = NULL;
}

void dsos_perror(const char *fmt, ...)
{
	int	i;
	va_list	ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);

	fprintf(stderr, "server  ");
	for (i = 0; i < g.num_servers; ++i)
		fprintf(stderr, "%3d ", i);
	fprintf(stderr, "\n");

	fprintf(stderr, "local:  ");
	for (i = 0; i < g.num_servers; ++i)
		fprintf(stderr, "%03d ", dsos_err_get_local(dsos_errno, i));
	fprintf(stderr, "\n");

	fprintf(stderr, "remote: ");
	for (i = 0; i < g.num_servers; ++i)
		fprintf(stderr, "%03d ", dsos_err_get_remote(dsos_errno, i));
	fprintf(stderr, "\n");
}

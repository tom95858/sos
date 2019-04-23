#include "dsos_priv.h"

/*
 * This allocates a vector with the last status of each DSOS
 * server from the most recent operation.
 */

static __thread int	*statuses = NULL;

static inline void err_alloc(void)
{
	if (!statuses)
		statuses = (int *)malloc(g.num_servers * sizeof(int));
	if (!statuses)
		dsos_fatal("out of memory\n");
}

void dsos_err_clear(void)
{
	err_alloc();
	bzero(statuses, g.num_servers * sizeof(int));
}

void dsos_err_set(int server_id, int status)
{
	err_alloc();
	statuses[server_id] = status;
}

int *dsos_err_get(void)
{
	return statuses;
}

int dsos_err_status(void)
{
	int	i, ret = 0;

	for (i = 0; i < g.num_servers; ++i)
		ret |= statuses[i];
	return ret!=0;
}

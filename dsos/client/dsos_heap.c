#include "dsos_priv.h"

/* A quick-and-dirty heap allocator. */

dsos_heap_t *dsos_heap_new(int num_frames)
{
	dsos_heap_t	*heap;

	heap = malloc(sizeof(dsos_heap_t));
	if (!heap)
		return NULL;
	heap->frames = calloc(num_frames, sizeof(dsos_heap_frame_t));
	if (!heap->frames) {
		free(heap);
		return NULL;
	}
	heap->num_frames = num_frames;
	heap->num_bytes  = num_frames * sizeof(dsos_heap_frame_t);
	return heap;
}

zap_err_t dsos_heap_map(dsos_heap_t *heap, dsos_conn_t *conn, zap_access_t acc)
{
	return zap_map(conn->ep, &conn->map, heap->frames, heap->num_bytes, acc);
}

void *dsos_heap_alloc(dsos_heap_t *heap, size_t len)
{
	int	i;

	if (len > HEAP_FRAME_SIZE)
		return NULL;
	for (i = 0; i < heap->num_frames; ++i) {
		if (!heap->frames[i].used) {
			heap->frames[i].used = 1;
			return heap->frames[i].buf;
		}
	}
	return NULL;
}

void dsos_heap_free(dsos_heap_t *heap, void *ptr)
{
	((dsos_heap_frame_t *)ptr)->used = 0;
}

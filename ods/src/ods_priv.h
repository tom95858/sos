/*
 * Copyright (c) 2013-2018 Open Grid Computing, Inc. All rights reserved.
 * Copyright (c) 2013 Sandia Corporation. All rights reserved.
 * Under the terms of Contract DE-AC04-94AL85000, there is a non-exclusive
 * license for use of this work by or on behalf of the U.S. Government.
 * Export of this program may require a license from the United States
 * Government.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the BSD-type
 * license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *      Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *
 *      Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 *      Neither the name of Sandia nor the names of any contributors may
 *      be used to endorse or promote products derived from this software
 *      without specific prior written permission.
 *
 *      Neither the name of Open Grid Computing nor the names of any
 *      contributors may be used to endorse or promote products derived
 *      from this software without specific prior written permission.
 *
 *      Modified source versions must be plainly marked as such, and
 *      must not be misrepresented as being the original software.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Author: Tom Tucker tom at ogc dot us
 */

#ifndef __ODS_PRIV_H
#define __ODS_PRIV_H
#include <ods/ods_atomic.h>
#include <ods/rbt.h>
#include <stdarg.h>
#include <stdint.h>
#include <time.h>
#include <sys/syscall.h>

/**
 * ods - A file backed object store
 *
 * There are two types of memory allocations supported: pagesets and
 * blocks. A pageset is a collection of ODS_PAGE sized chunks of
 * memory that are contiguous. A block is a smaller chunk of memory
 * that is part of a subdivided pageset. Blocks are kept in a table
 * indexed by i_log2(desired_size) - i_log2(ODS_MIN_SIZE). If this
 * table is empty, a ODS_PAGE chunk is allocated and subdivided in
 * blocks that are chained on a list and added to this table.
 *
 *   7   6   5   4   3   2   1   0
 * +---------------+---------------+
 * | o | o | o | o | o | o | o | o |
 * +-+---+---+---+---+---+---+---+-+
 *   |   |   |   |   |   |   |   |
 *   |   |   |   |   +---+---+---+---: If bit4==1, the Log2 size of the block
 *   |   |   |   +-------------------: The index is valid
 *   |   |   +-----------------------: The next page is part of this chunk
 *   |   +---------------------------: The prev page is part of this chunk
 *   +-------------------------------: The page is part of an allocation
 *
 *
 */

/*
 * The ODS obj map is a partial map of the ODS object file.
 */
struct ods_map_s {
	/*
	 * Reference count for the map. Every ods_obj has a
	 * reference. When the last reference is dropped, the map is a
	 * candidate to be cleaned up by the garbage collection thread
	 * and the extent munmap'd.
	 */
	ods_atomic_t refcount;

	/* The ODS for this map */
	ods_t ods;

	/* Pointer to the data in memory */
	unsigned char *data;

	/* time() last used */
	time_t last_used;

	struct map_key_s {
		loff_t off;		/* Map offset */
		size_t len;		/* This length of this map in Bytes */
	} map;
	struct rbn rbn;		/* Active map tree */
	LIST_ENTRY(ods_map_s) entry; /* Queued for deletion */
};

typedef struct ods_dirty_s {
	ods_ref_t start;
	ods_ref_t end;
	ods_t ods;
	struct rbn rbn;
} *ods_dirty_t;

struct ods_s {
	/* The path to the file on disk */
	char *path;

	/* Open permissions */
	ods_perm_t o_perm;

	/* The open file descriptor */
	int obj_fd;
	size_t obj_sz;

	/* The page-file file descriptor */
	int pg_fd;
	size_t pg_sz;

	/*
	 * The mapping generation number. Used to detect if another
	 * process extended the page file and we need to remap it.
	 */
	uint64_t pg_gen;

	/* Pointer to the page-file data in memory */
	struct ods_pgt_s *lck_table; /* never grows, persistent until close */
	struct ods_pgt_s *pg_table; /* grows on ods_extend */

	/* Current ODS map size for new maps in bytes */
	size_t obj_map_sz;

	/* Tree of object maps. Key is file offset and map length. */
	ods_map_t last_map;
	struct rbt map_tree;

	/* Local lock for this ODS instance */
	pthread_mutex_t lock;

	/* The object list */
	ods_atomic_t obj_count;
	LIST_HEAD(obj_list_head, ods_obj_s) obj_list;

	/* The dirty tree */
	struct rbt dirty_tree;

	LIST_ENTRY(ods_s) entry;
};

#define ODS_OBJ_SIGNATURE "OBJSTORE"
#define ODS_PGT_SIGNATURE "PGTSTORE"

#define ODS_PAGE_SIZE	 4096
#define ODS_PAGE_SHIFT	 12
#define ODS_PAGE_MASK	 ~(ODS_PAGE_SIZE-1)
#define ODS_GRAIN_SIZE	 32
#define ODS_GRAIN_SHIFT	 5
#define ODS_BKT_TABLE_SZ 64

#define ODS_F_IDX_VALID		0x10 /* Bucket index is valid */
#define ODS_F_IN_BKT		0x20 /* In the bucket table */
#define ODS_F_ALLOCATED		0x80 /* Page is allocated */

/*
 *              Page Table
 *              +----------+
 *   pg_free -->| pg_next  o----+
 *              +----------+    |
 *     +------->| blk_next o----^--+
 *     |        +----------+	|  |
 *     |   +----o pg_next  |<---+  |
 *     |   |    +----------+	   |
 *     |   | +--o blk_next |<------+
 *     |   | |  +----------+
 *     |   | +->| blk_next |
 *     |   |    +----------+
 *     |   +--->| pg_next  |
 *     |        +----------+
 *     |        S          S
 *     |        +----------+
 *     |        |          |
 *     |        +----------+
 *     |
 *     |        Bucket Table
 *     |   ---- +----------+
 *     |    ^   |          |
 *     |    |   +----------+
 *     +----^---o blk_next |
 *          |   +----------+
 *         64   S          S
 *          |   +----------+
 *          v   |          |
 *         ---- +----------+
 *
 * Buckets are arrays of blocks of the same size. All block sizes are
 * restricted to 32B ... 2048B in 32B increments; which is 63 size
 * classes 0 == 32B, 62 == 2048B. Objects > 2048B consume an integral
 * number of pages.
 *
 * The 128b pg_bits field in the page table has a bit for each block in
 * the page which is a maximum of 128 blocks per page.
 */
typedef struct ods_pg_s {
	uint64_t pg_flags:8;	/* Indicates if the page is allocated and whether or not it is bucket list member */
	uint64_t pg_bkt_idx:8;	/* If page contains blocks, this is the index in the bucket table */
	uint64_t pg_next;	/* Page no of next extent */
	uint64_t pg_count;	/* number of pages in this extent */
	uint64_t pg_bits[2];	/* 1 if blk allocated, 0 if block is free */
} *ods_pg_t;

typedef struct ods_lock_s {
	union {
		struct ods_spin_lock_s {
			ods_atomic_t lock_word;
			ods_atomic_t contested;
			uint64_t owner;
		} spin;
		pthread_mutex_t mutex;
	};
} ods_lock_t;

#pragma pack(4)

#define ODS_PGT_PFX_SZ  (8 +				\
			 44 +				\
			 sizeof(struct ods_version_s) +	\
			 (3 * sizeof(uint64_t)) +	\
			 sizeof(ods_lock_t)		\
			 )
#define ODS_LOCK_MEM_SZ	(ODS_PAGE_SIZE - ODS_PGT_PFX_SZ)
#define ODS_LOCK_CNT	(ODS_LOCK_MEM_SZ / sizeof(ods_lock_t))

typedef struct ods_bkt_s {
	uint64_t pg_next;	/* next bucket */
} *ods_bkt_t;

typedef struct ods_pgt_s {
	char pg_signature[8];	 /* pgt signature 'PGTSTORE' */
	union {
		char _pg_commit_id[41];	 /* git SHA1 hash is 40B */
		uint8_t pg_opts[41];	 /* config options */
	};
	struct ods_version_s pg_vers; /* PGT version */
	uint64_t pg_gen;	 /* generation number */
	uint64_t pg_free;	 /* first free page number */
	uint64_t pg_count;	 /* count of pages */
	ods_lock_t pgt_lock;	 /* inter-process page-table lock */
	/* Inter-process locks for applications */
	union {
		unsigned char lock_mem[ODS_LOCK_MEM_SZ];
		ods_lock_t lck_tbl[0];
	};
	/* Should begin on a 4096B boundary */
	struct ods_bkt_s bkt_table[ODS_BKT_TABLE_SZ];
	struct ods_pg_s pg_pages[0];/* array of page control information */
} *ods_pgt_t;

struct ods_obj_data_s {
	char obj_signature[8];	 /* obj signature 'OBJSTORE' */
};
#pragma pack()

#define ODS_UDATA_SIZE (ODS_PAGE_SIZE - sizeof(struct ods_obj_data_s))

#define ODS_PGTBL_MIN_SZ	(4096)
#define ODS_PGTBL_MIN_SZ	(4096)
#define ODS_OBJ_MIN_SZ		(16 * 4096)

/* Garbage collection timeout */
#define ODS_DEF_GC_TIMEOUT	10 /* 10 seconds */
extern time_t __ods_gc_timeout;

/* Default map size */
#define ODS_MIN_MAP_SZ	(64 * ODS_PAGE_SIZE)	/* 256K */
#define ODS_DEF_MAP_SZ	(256 * ODS_PAGE_SIZE)	/* 1M */
#define ODS_MAX_MAP_SZ	(512 * ODS_DEF_MAP_SZ)	/* 512M */

extern uint64_t __ods_def_map_sz;

/* ODS Debug True/False */
extern int __ods_debug;

/* Log file pointer and mask */
extern FILE *__ods_log_fp;
extern uint64_t __ods_log_mask;

static inline void ods_log(int level, const char *func, int line, char *fmt, ...)
{
	va_list ap;
	pid_t tid;
	struct timespec ts;

	if (!__ods_log_fp)
		return;

	if (0 ==  (level & __ods_log_mask))
		return;

	tid = (pid_t) syscall (SYS_gettid);
	clock_gettime(CLOCK_REALTIME, &ts);
	va_start(ap, fmt);
	fprintf(__ods_log_fp, "[%d] %d.%09d: ods[%d] @ %s:%d | ",
		tid, ts.tv_sec, ts.tv_nsec, level, func, line);
	vfprintf(__ods_log_fp, fmt, ap);
	fflush(__ods_log_fp);
}

#define ods_lfatal(fmt, ...) ods_log(ODS_LOG_FATAL, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define ods_lerror(fmt, ...) ods_log(ODS_LOG_ERROR, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define ods_lwarn(fmt, ...) ods_log(ODS_LOG_WARN, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define ods_linfo(fmt, ...) ods_log(ODS_LOG_INFO, __func__, __LINE__, fmt, ##__VA_ARGS__)
#define ods_ldebug(fmt, ...) ods_log(ODS_LOG_DEBUG, __func__, __LINE__, fmt, ##__VA_ARGS__)

void __ods_obj_delete(ods_obj_t obj);
#define ODS_ROUNDUP(_sz_, _align_) (((_sz_) + (_align_) - 1) & ~((_align_)-1))

#endif

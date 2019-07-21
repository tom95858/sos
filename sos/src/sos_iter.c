/*
 * Copyright (c) 2018 Open Grid Computing, Inc. All rights reserved.
 * Copyright (c) 2014 Sandia Corporation. All rights reserved.
 *
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

#include <sys/queue.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <assert.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <limits.h>
#include <errno.h>

#include <sos/sos.h>
#include <ods/ods.h>
#include <ods/ods_idx.h>
#include "sos_priv.h"

static int __attr_join_idx(sos_attr_t filt_attr, sos_attr_t attr);

static int __sos_filter_key_set(sos_filter_t filt, sos_key_t key,
				int min_not_max, int last_match);
static sos_filter_cond_t __sos_find_filter_condition(sos_filter_t filt,
						     int attr_id);
static sos_obj_t next_match(sos_filter_t filt);
static sos_obj_t prev_match(sos_filter_t filt);

/**
 * \brief Create a SOS iterator from an index
 *
 * Create an iterator on the specified index.
 *
 * \param index The index handle
 *
 * \retval sos_iter_t for the specified index
 * \retval NULL       If there was an error creating the iterator.
 */
sos_iter_t sos_index_iter_new(sos_index_t index)
{
	sos_iter_t i;

	i = malloc(sizeof *i);
	if (!i)
		return NULL;
	i->attr = NULL;
	i->index = index;
	i->iter = ods_iter_new(index->idx);
	if (!i->iter)
		goto err;
	return i;
 err:
	if (i)
		free(i);
	return NULL;
}

/**
 * \brief Create a SOS iterator from an attribute index
 *
 * Create an iterator on the specified attribute. If there is no index
 * defined on the iterator, the function will fail.
 *
 * \param attr The schema attribute handle
 *
 * \retval sos_iter_t for the specified attribute
 * \retval NULL       The attribute is not indexed
 */
sos_iter_t sos_attr_iter_new(sos_attr_t attr)
{
	sos_iter_t iter;
	sos_index_t index = sos_attr_index(attr);

	if (!index) {
		errno = EINVAL;
		return NULL;
	}

	iter = sos_index_iter_new(index);
	if (iter)
		iter->attr = attr;

	return iter;
}

/**
 * \brief Return the attribute associated with the iterator
 *
 * \param iter The iterator handle
 * \returns A pointer to the attribute or NULL if the iterator is not
 *          associated with a schema attribute.
 */
sos_attr_t sos_iter_attr(sos_iter_t iter)
{
	return iter->attr;
}

/**
 * \brief Set iterator behavior flags
 *
 * \param i The iterator
 * \param flags The iterator flags
 * \retval 0 The flags were set successfully
 * \retval EINVAL The iterator or flags were invalid
 */
int sos_iter_flags_set(sos_iter_t iter, sos_iter_flags_t flags)
{
	return ods_iter_flags_set(iter->iter, flags);
}

/**
 * \brief Get the iterator behavior flags
 *
 * \param iter The iterator
 * \retval The sos_iter_flags_t for the iterator
 */
sos_iter_flags_t sos_iter_flags_get(sos_iter_t iter)
{
	return (sos_iter_flags_t)ods_iter_flags_get(iter->iter);
}

/**
 * \brief Return the number of positions in the iterator
 * \param iter The iterator handle
 * \returns The cardinality of the iterator
 */
uint64_t sos_iter_card(sos_iter_t iter)
{
	struct ods_idx_stat_s sb;
	int rc = ods_idx_stat(ods_iter_idx(iter->iter), &sb);
	if (rc)
		return 0;
	return sb.cardinality;
}

/**
 * \brief Return the number of duplicates in the index
 * \returns The count of duplicates
 */
uint64_t sos_iter_dups(sos_iter_t iter)
{
	struct ods_idx_stat_s sb;
	int rc = ods_idx_stat(ods_iter_idx(iter->iter), &sb);
	if (rc)
		return 0;
	return sb.duplicates;
}

#define FNV_32_PRIME 0x01000193
static uint32_t fnv_hash_a1_32(const void *str, int len, uint32_t seed)
{
	uint32_t h = seed;
	const unsigned char *end = (unsigned char *)str + len;
	const unsigned char *s;
	for (s = str; s < end; s++) {
		h ^= *s;
		h *= FNV_32_PRIME;
	}

	return (uint32_t)h;
}

/**
 * \brief Returns the current iterator position
 *
 * \param i The iterator handle
 * \param pos The sos_pos_t that will receive the position value.
 * \returns The current iterator position or 0 if position is invalid
 */
int sos_iter_pos_get(sos_iter_t iter, sos_pos_t *pos)
{
	struct timeval tv;
	ods_obj_t pos_obj;
	sos_t sos = iter->index->sos;
	int rc;
	uint32_t key;
	ods_idx_data_t pos_data;
	SOS_KEY(pos_key);

	rc = gettimeofday(&tv, NULL);
	if (rc)
		return rc;

	/* Create a SOS pos object to track this */
	ods_lock(sos->pos_ods, 0, NULL);
	rc = ENOMEM;
	pos_obj = ods_obj_alloc_extend(sos->pos_ods, sizeof(struct sos_pos_data_s), 64 * 1024);
	if (!pos_obj)
		goto err_0;

	rc = ods_iter_pos_get(iter->iter, &SOS_POS(pos_obj)->ods_pos);
	if (rc)
		goto err_1;

	strncpy(SOS_POS(pos_obj)->name, iter->index->name, SOS_INDEX_NAME_LEN);
	SOS_POS(pos_obj)->create_secs = tv.tv_sec;
	SOS_POS(pos_obj)->create_usecs = tv.tv_usec;

	/* Create the key */
	while (1) {
		key = fnv_hash_a1_32(SOS_POS(pos_obj)->name, SOS_INDEX_NAME_LEN, 0);
		key = fnv_hash_a1_32(&SOS_POS(pos_obj)->create_secs, sizeof(uint32_t), key);
		key = fnv_hash_a1_32(&SOS_POS(pos_obj)->create_usecs, sizeof(uint32_t), key);
		key = fnv_hash_a1_32(&SOS_POS(pos_obj)->ods_pos, sizeof(uint64_t), key);
		SOS_POS(pos_obj)->key = key;

		/* See if this key is already used */
		ods_key_set(pos_key, &key, sizeof(uint32_t));
		rc = ods_idx_find(sos->pos_idx, pos_key, &pos_data);
		if (!rc) {
			/* bump the create_usecs and regenerate the hash */
			SOS_POS(pos_obj)->create_usecs ++;
			continue;
		}
		/* Save the pos object */
		pos_data.uint64_[0] = ods_obj_ref(pos_obj);
		pos_data.uint64_[1] = 0;
		rc = ods_idx_insert(sos->pos_idx, pos_key, pos_data);
		if (rc)
			goto err_2;
		break;
	}
	ods_obj_put(pos_obj);
	ods_unlock(sos->pos_ods, 0);
	*pos = key;
	return 0;

 err_2:
	ods_iter_pos_put(iter->iter, &SOS_POS(pos_obj)->ods_pos);
 err_1:
	ods_obj_delete(pos_obj);
	ods_obj_put(pos_obj);
 err_0:
	ods_unlock(sos->pos_ods, 0);
	return rc;
}

int sos_pos_from_str(sos_pos_t *pos, const char *str)
{
	const char *src = str;
	unsigned char *dst = (unsigned char *)pos;
	int i;
	for (i = 0; i < sizeof(*pos); i++) {
		int rc = sscanf(src, "%02hhX", dst);
		if (rc != 1)
			return EINVAL;
		src += 2; dst++;
	}
	return 0;
}

const char *sos_pos_to_str(sos_pos_t pos)
{
	int i;
	char *pos_str;
	unsigned char *src = (unsigned char *)&pos;
	char *dst = malloc((2 * sizeof(pos)) + 1);
	if (!dst)
		return NULL;
	pos_str = dst;
	for (i = 0; i < sizeof(pos); i++) {
		sprintf(dst, "%02hhX", *src);
		src += 1;
		dst += 2;
	}
	*dst = '\0';
	return pos_str;
}

void sos_pos_str_free(char *str)
{
	free(str);
}

/**
 * \brief Sets the current iterator position
 *
 * Set the iterator position at the location specified by the \c pos
 * parameter. Pos objects are single use, which means that after they
 * are used, the pos is deleted and cannot be reused.
 *
 * \param i The iterator handle
 * \param pos The iterator cursor position
 * \retval 0 Success
 * \retval ENOENT The position was not found, or has already been used
 * \retval EINVAL The position object is for a different index
 */
int sos_iter_pos_set(sos_iter_t iter, const sos_pos_t pos)
{
	ods_obj_t pos_obj;
	sos_t sos = iter->index->sos;
	int rc;
	ods_idx_data_t pos_data;
	SOS_KEY(pos_key);

	ods_lock(sos->pos_ods, 0, NULL);

	/* Look up the position */
	ods_key_set(pos_key, &pos, sizeof(sos_pos_t));
	rc = ods_idx_find(sos->pos_idx, pos_key, &pos_data);
	if (rc)
		/* This position does not exist */
		goto out_0;

	/* Instantiate the pos object */
	pos_obj = ods_ref_as_obj(sos->pos_ods, pos_data.uint64_[0]);
	if (!pos_obj) {
		rc = ENOENT;
		goto out_1;
	}

	/* Check that the iterator index matches the position index */
	if (strncmp(SOS_POS(pos_obj)->name, iter->index->name, SOS_INDEX_NAME_LEN)) {
		/* Position is for a different index */
		rc = EINVAL;
		goto out_2;
	}

	/* Set the iterator position */
	rc = ods_iter_pos_set(iter->iter, &SOS_POS(pos_obj)->ods_pos);

 out_2:
	ods_obj_delete(pos_obj);
	ods_obj_put(pos_obj);
 out_1:
	ods_idx_delete(sos->pos_idx, pos_key, &pos_data);
 out_0:
	ods_unlock(sos->pos_ods, 0);
	return rc;
}

int sos_iter_pos_put_no_lock(sos_iter_t iter, const sos_pos_t pos)
{
	ods_obj_t pos_obj;
	sos_t sos = iter->index->sos;
	int rc;
	ods_idx_data_t pos_data;
	SOS_KEY(pos_key);

	/* Look up the position */
	ods_key_set(pos_key, &pos, sizeof(sos_pos_t));
	rc = ods_idx_find(sos->pos_idx, pos_key, &pos_data);
	if (rc)
		/* This position does not exist */
		goto out_0;

	/* Instantiate the pos object */
	pos_obj = ods_ref_as_obj(sos->pos_ods, pos_data.uint64_[0]);
	if (!pos_obj) {
		rc = ENOENT;
		goto out_1;
	}

	/* Check that the iterator index matches the position index */
	if (strncmp(SOS_POS(pos_obj)->name, iter->index->name, SOS_INDEX_NAME_LEN)) {
		/* Position is for a different index */
		rc = EINVAL;
		goto out_2;
	}

	/* Put the iterator position */
	rc = ods_iter_pos_put(iter->iter, &SOS_POS(pos_obj)->ods_pos);

 out_2:
	ods_obj_delete(pos_obj);
	ods_obj_put(pos_obj);
 out_1:
	ods_idx_delete(sos->pos_idx, pos_key, &pos_data);
 out_0:
	return rc;
}

/**
 * \brief Indicates to the iterator that this position is no longer in-use
 *
 * \param i The iterator handle
 * \param pos The iterator cursor position
 * \retval 0 Success
 * \retval ENOENT The iterator position is invalid
 */
int sos_iter_pos_put(sos_iter_t iter, const sos_pos_t pos)
{
	int rc;
	ods_lock(iter->index->sos->pos_ods, 0, NULL);
	rc = sos_iter_pos_put_no_lock(iter, pos);
	ods_unlock(iter->index->sos->pos_ods, 0);
	return rc;
}

/**
 * \brief Release the resources associated with a SOS iterator
 *
 * \param iter	The iterator returned by \c sos_new_iter
 */
void sos_iter_free(sos_iter_t iter)
{
	ods_iter_delete(iter->iter);
	free(iter);
}

/**
 * \brief Return the object at the current iterator position
 *
 * \param iter	The iterator handle
 * \return sos_obj_t at the current position
 */
sos_obj_t sos_iter_obj(sos_iter_t i)
{
	sos_obj_ref_t idx_ref;
	sos_obj_t obj;
	idx_ref.idx_data = ods_iter_data(i->iter);
	if (!idx_ref.ref.obj)
		return NULL;
	obj = sos_ref_as_obj(i->index->sos, idx_ref);
	if (!obj)
		errno = EINVAL;
	return obj;
}

/**
 * \brief Return the object reference at the current iterator position
 *
 * \param iter	The iterator handle
 * \return sos_obj_ref_t at the current position
 */
sos_obj_ref_t sos_iter_ref(sos_iter_t i)
{
	sos_obj_ref_t idx_ref;
	idx_ref.idx_data = ods_iter_data(i->iter);
	return idx_ref;
}

/**
 * \brief Remove the index entry at the current iterator position
 *
 * Removes the index entry at the current cursor position.
 * After removal, the iterator points at the next entry if it
 * exists, or empty if the tail was deleted.
 *
 * \param iter The iterator handle
 * \return 0 on success.
 * \return Error code on failure.
 */
int sos_iter_entry_remove(sos_iter_t iter)
{
	ods_idx_data_t data;
	return ods_iter_entry_delete(iter->iter, &data);
}

/**
 * \brief Position the iterator at next object in the index
 *
 * Advance the iterator position to the next entry.
 *
 * \param iter The iterator handle
 *
 * \retval 0 The iterator is positioned at the next object in the index
 * \retval ENOENT No more entries in the index
 */
int sos_iter_next(sos_iter_t i)
{
	return ods_iter_next(i->iter);
}

/**
 * \brief Retrieve the next object from the iterator
 *
 * Advance the iterator position to the previous entry.
 *
 * \param i Iterator handle
 *
 * \returns 0  The iterator is positioned at the previous entry
 * \returns ENOENT If no more matching records were found.
 */
int sos_iter_prev(sos_iter_t i)
{
	return ods_iter_prev(i->iter);
}

/**
 * Position the iterator at the first object.
 *
 * \param i	The iterator handle

 * \return 0 The iterator is positioned at the first object in the index
 * \return ENOENT The index is empty
 */
int sos_iter_begin(sos_iter_t i)
{
	/* TODO clean if restarting */

	/* Get first partition */
	return ods_iter_begin(i->iter);
}

/**
 * Position the iterator at the last object in the index
 *
 * \param i The iterator handle
 * \return 0 The iterator is positioned at the last object in the index
 * \return ENOENT The index is empty
 */
int sos_iter_end(sos_iter_t i)
{
	return ods_iter_end(i->iter);
}

/**
 * \brief Position the iterator at the supremum of the specified key
 *
 * Position the iterator at the object whose key is the least
 * upper bound of the specified key.
 *
 * If the supremum is a duplicate key, the cursor is positioned at
 * the first instance of the key.
 *
 * This behavior can be changed using the sos_iter_flags_set()
 * function to set the SOS_ITER_F_SUP_LAST_DUP option. This will cause
 * this function to place the iterator position at the last
 * duplicate. Note that this _may_ break the axiom that INF(set) <=
 * SUP(set)
 *
 * \param i Pointer to the iterator
 * \param key The key.
 *
 * \retval 0 The iterator is positioned at the supremum
 * \retval ENOENT No supremum exists
 */
int sos_iter_sup(sos_iter_t i, sos_key_t key)
{
	return ods_iter_find_lub(i->iter, key);
}

/**
 * \brief Position the iterator at the infinum of the specified key.
 *
 * Position the iterator at the object whose key is the greatest
 * lower bound of the specified key.
 *
 * If the infininum is a duplicate key, the cursor is positioned at
 * the first instance of the key.
 *
 * This behavior can be changed using the sos_iter_flags_set()
 * function to set the SOS_ITER_F_INF_LAST_DUP option. This will cause
 * this function to place the iterator position at the last
 * duplicate. Note that this _may_ break the axiom that INF(set) <=
 * SUP(set)
 *
 * \param i Pointer to the iterator
 * \param key The key.
 *
 * \retval 0 if the iterator is positioned at the infinum
 * \retval ENOENT if the infinum does not exist
 */
int sos_iter_inf(sos_iter_t i, sos_key_t key)
{
	return ods_iter_find_glb(i->iter, key);
}

/**
 * \brief Compare iterator object's key with other key.
 *
 * This function compare the key of the object pointed by the iterator with the
 * other key. This is a convenience routine and is equivalent to the
 * following code sequence:
 *
 *     sos_key_t iter_key = sos_iter_key(iter);
 *     int64_t rc = sos_key_cmp(attr, iter_key, other);
 *     sos_key_put(iter_key);
 *
 * \param iter	The iterator handle
 * \param other	The other key
 * \retval <0	iter < other
 * \retval 0	iter == other
 * \retval >0	iter > other
 */
int64_t sos_iter_key_cmp(sos_iter_t iter, sos_key_t key)
{
	int64_t rc;
	ods_key_t iter_key = ods_iter_key(iter->iter);
	rc = ods_key_cmp(iter->index->idx, iter_key, key);
	ods_obj_put(iter_key);
	return rc;
}

/**
 * \brief Position the iterator at the specified key
 *
 * If the index contains duplicate keys, the iterator will be
 * positioned at the first instance of the specified key.
 *
 * \param iter  Handle for the iterator.
 * \param key   The key for the iterator. The appropriate index will
 *		be searched to find the object that matches the key.
 *
 * \retval 0 Iterator is positioned at matching object.
 * \retval ENOENT No matching object was found.
 */
int sos_iter_find(sos_iter_t iter, sos_key_t key)
{
	return ods_iter_find(iter->iter, key);
}

/**
 * \brief Position the iterator at the first instance of the specified key
 *
 * \param iter  Handle for the iterator.
 * \param key   The key for the iterator. The appropriate index will
 *		be searched to find the object that matches the key.
 *
 * \retval 0 Iterator is positioned at matching object.
 * \retval ENOENT No matching object was found.
 */
int sos_iter_find_first(sos_iter_t iter, sos_key_t key)
{
	return ods_iter_find_first(iter->iter, key);
}

/**
 * \brief Position the iterator at the last instance of the specified key
 *
 * \param iter  Handle for the iterator.
 * \param key   The key for the iterator. The appropriate index will
 *		be searched to find the object that matches the key.
 *
 * \retval 0 Iterator is positioned at matching object.
 * \retval ENOENT No matching object was found.
 */
int sos_iter_find_last(sos_iter_t iter, sos_key_t key)
{
	return ods_iter_find_last(iter->iter, key);
}

/**
 * \brief Return the key at the current iterator position
 *
 * Return the key associated with the current iterator position. This
 * key is persistent and reference counted. Use the sos_key_put()
 * function to drop the reference given by this function when finished
 * with the key.
 *
 * \param iter	The iterator handle
 * \return sos_key_t at the current position
 */
sos_key_t sos_iter_key(sos_iter_t iter)
{
	return ods_iter_key(iter->iter);
}
static int lt_fn(sos_value_t obj_value, sos_value_t cond_value, int *ret)
{
	int rc = *ret = sos_value_cmp(obj_value, cond_value);
	return (rc < 0);
}

static int le_fn(sos_value_t obj_value, sos_value_t cond_value, int *ret)
{
	int rc = *ret = sos_value_cmp(obj_value, cond_value);
	return (rc <= 0);
}

static int eq_fn(sos_value_t obj_value, sos_value_t cond_value, int *ret)
{
	int rc = *ret = sos_value_cmp(obj_value, cond_value);
	return (rc == 0);
}

static int ne_fn(sos_value_t obj_value, sos_value_t cond_value, int *ret)
{
	int rc = *ret = sos_value_cmp(obj_value, cond_value);
	return (rc != 0);
}

static int ge_fn(sos_value_t obj_value, sos_value_t cond_value, int *ret)
{
	int rc = *ret = sos_value_cmp(obj_value, cond_value);
	return (rc >= 0);
}

static int gt_fn(sos_value_t obj_value, sos_value_t cond_value, int *ret)
{
	int rc = *ret = sos_value_cmp(obj_value, cond_value);
	return (rc > 0);
}

sos_filter_fn_t fn_table[] = {
	[SOS_COND_LT] = lt_fn,
	[SOS_COND_LE] = le_fn,
	[SOS_COND_EQ] = eq_fn,
	[SOS_COND_GE] = ge_fn,
	[SOS_COND_GT] = gt_fn,
	[SOS_COND_NE] = ne_fn,
};

/**
 * \brief allocate a Sos Filter
 *
 * This function inherits the iterator reference from the caller.
 *
 * \param iter The iterator handle.
 * \returns A new filter object or NULL if there is an error
 */
sos_filter_t sos_filter_new(sos_iter_t iter)
{
	sos_filter_t f = calloc(1, sizeof *f);
	if (f) {
		TAILQ_INIT(&f->cond_list);
		f->iter = iter;
		f->last_match = ODS_OBJ_INIT(f->last_match_obj,
					     &f->last_match_key_data,
					     SOS_STACK_KEY_SIZE);
	}
	return f;
}

void sos_filter_free(sos_filter_t f)
{
	sos_filter_cond_t cond;
	while (!TAILQ_EMPTY(&f->cond_list)) {
		cond = TAILQ_FIRST(&f->cond_list);
		TAILQ_REMOVE(&f->cond_list, cond, entry);
		free(cond);
	}
	sos_iter_free(f->iter);
	free(f);
}

int sos_filter_flags_set(sos_filter_t f, sos_iter_flags_t flags)
{
	return sos_iter_flags_set(f->iter, flags);
}

sos_iter_flags_t sos_filter_flags_get(sos_filter_t f)
{
	return sos_iter_flags_get(f->iter);
}

static int __attr_join_idx(sos_attr_t filt_attr, sos_attr_t attr)
{
	int idx;
	int attr_id;
	sos_array_t attr_ids;

	if (sos_attr_type(filt_attr) != SOS_TYPE_JOIN)
		return -1;

	/*
	 * If the filter iterator attribute is a JOIN,
	 * check if the condition attribute is a member
	 */
	attr_id = sos_attr_id(attr);
	attr_ids = sos_attr_join_list(filt_attr);
	for (idx = 0; idx < attr_ids->count; idx++) {
		if (attr_ids->data.uint32_[idx] == attr_id)
			return idx;
	}
	return -1;
}

static void
__insert_filter_cond_fwd(sos_attr_t filt_attr, struct sos_cond_list *head,
			 struct sos_filter_cond_s *new_cond)
{
	int filt_attr_id, new_attr_id, new_join_idx;
	struct sos_filter_cond_s *cond;

	if (TAILQ_EMPTY(head)) {
		TAILQ_INSERT_TAIL(head, new_cond, entry);
		return;
	}

	filt_attr_id = sos_attr_id(filt_attr);
	new_attr_id = sos_attr_id(new_cond->attr);
	new_join_idx = __attr_join_idx(filt_attr, new_cond->attr);

	TAILQ_FOREACH(cond, head, entry) {
		if (new_join_idx >= 0) {
			int cond_join_idx = __attr_join_idx(filt_attr, cond->attr);
			/* New condition is in the iterators join attr */
			if (cond_join_idx < 0) {
				/* cond not in join_attr, new_cond takes prec. */
				TAILQ_INSERT_BEFORE(cond, new_cond, entry);
				return;
			} else if (new_join_idx < cond_join_idx) {
				/* cond join index greater, new_cond takes prec. */
				TAILQ_INSERT_BEFORE(cond, new_cond, entry);
				return;
			} else if (new_join_idx > cond_join_idx) {
				/* cond's join idx is before new_cond in
				 * the key, but there may be other conds
				 * that also take precedence */
				continue;
			} else if (new_cond->cond > cond->cond) {
				/* same join attr, condition takes prec. */
				TAILQ_INSERT_BEFORE(cond, new_cond, entry);
				return;
			} else if (new_cond->cond < cond->cond) {
				TAILQ_INSERT_AFTER(head, cond, new_cond, entry);
				return;
			} else {
				/* Found duplicate condition, remove it */
				sos_value_put(new_cond->value);
				free(new_cond);
				return;
			}
		} else if (filt_attr_id == new_attr_id) {
			/* new cond is on iterator attribute */
			if (sos_attr_id(cond->attr) != filt_attr_id) {
				/* cond is not on iterator attribute, new_cond takes prec. */
				TAILQ_INSERT_BEFORE(cond, new_cond, entry);
				return;
			} else if (new_cond->cond > cond->cond) {
				/* cond is also on iterator attr, comparator defines prec. */
				TAILQ_INSERT_BEFORE(cond, new_cond, entry);
				return;
			} else if (new_cond->cond < cond->cond) {
				TAILQ_INSERT_AFTER(head, cond, new_cond, entry);
				return;
			} else {
				/* Found duplicate condition, remove it */
				sos_value_put(new_cond->value);
				free(new_cond);
				return;
			}
		} else if (new_attr_id == sos_attr_id(cond->attr)) {
			/* Neiter condition is on filter iter, condition takes precedence */
			if (new_cond->cond > cond->cond) {
				TAILQ_INSERT_BEFORE(cond, new_cond, entry);
				return;
			} else if (new_cond->cond < cond->cond) {
				TAILQ_INSERT_AFTER(head, cond, new_cond, entry);
				return;
			} else {
				/* Found duplicate condition, remove it */
				sos_value_put(new_cond->value);
				free(new_cond);
				return;
			}
		}
		/*
		 * New attribute doesn't match the condition and is
		 * not on the iterator attribute, keep going to see if
		 * we find ourselves.
		 */
	}
	/* No other rule using this attribute, append to tail */
	TAILQ_INSERT_TAIL(head, new_cond, entry);
}

static void
__insert_filter_cond_bkwd(sos_attr_t filt_attr, struct sos_cond_list *head,
			  struct sos_filter_cond_s *new_cond)
{
	int filt_attr_id, new_attr_id, new_join_idx;
	struct sos_filter_cond_s *cond;

	if (TAILQ_EMPTY(head)) {
		TAILQ_INSERT_TAIL(head, new_cond, entry);
		return;
	}

	filt_attr_id = sos_attr_id(filt_attr);
	new_attr_id = sos_attr_id(new_cond->attr);
	new_join_idx = __attr_join_idx(filt_attr, new_cond->attr);

	TAILQ_FOREACH(cond, head, entry) {
		if (new_join_idx >= 0) {
			int cond_join_idx = __attr_join_idx(filt_attr, cond->attr);
			/* New condition is in the iterators join attr */
			if (cond_join_idx < 0) {
				/* cond not in join_attr, new_cond takes prec. */
				TAILQ_INSERT_BEFORE(cond, new_cond, entry);
				return;
			} else if (new_join_idx < cond_join_idx) {
				/* cond join index greater, new_cond takes prec. */
				TAILQ_INSERT_BEFORE(cond, new_cond, entry);
				return;
			} else if (new_join_idx > cond_join_idx) {
				/* cond's join idx is before new_cond in
				 * the key, but there may be other conds
				 * that also take precedence */
				continue;
			} else if (new_cond->cond < cond->cond) {
				/* same join attr, condition takes prec. */
				TAILQ_INSERT_BEFORE(cond, new_cond, entry);
				return;
			} else if (new_cond->cond > cond->cond) {
				TAILQ_INSERT_AFTER(head, cond, new_cond, entry);
				return;
			} else {
				/* Found duplicate condition, remove it */
				sos_value_put(new_cond->value);
				free(new_cond);
				return;
			}
		} else if (filt_attr_id == new_attr_id) {
			/* new cond is on iterator attribute */
			if (sos_attr_id(cond->attr) != filt_attr_id) {
				/* cond is not on iterator attribute, new_cond takes prec. */
				TAILQ_INSERT_BEFORE(cond, new_cond, entry);
				return;
			} else if (new_cond->cond < cond->cond) {
				/* cond is also on iterator attr, comparator defines prec. */
				TAILQ_INSERT_BEFORE(cond, new_cond, entry);
				return;
			} else if (new_cond->cond > cond->cond) {
				TAILQ_INSERT_AFTER(head, cond, new_cond, entry);
				return;
			} else {
				/* Found duplicate condition, remove it */
				sos_value_put(new_cond->value);
				free(new_cond);
				return;
			}
		} else if (new_attr_id == sos_attr_id(cond->attr)) {
			/* Neiter condition is on filter iter, condition takes precedence */
			if (new_cond->cond < cond->cond) {
				TAILQ_INSERT_BEFORE(cond, new_cond, entry);
				return;
			} else if (new_cond->cond > cond->cond) {
				TAILQ_INSERT_AFTER(head, cond, new_cond, entry);
				return;
			} else {
				/* Found duplicate condition, remove it */
				sos_value_put(new_cond->value);
				free(new_cond);
				return;
			}
		}
		/*
		 * New attribute doesn't match the condition and is
		 * not on the iterator attribute, keep going to see if
		 * we find ourselves.
		 */
	}
	/* No other rule using this attribute, append to tail */
	TAILQ_INSERT_TAIL(head, new_cond, entry);
}

/*
 * Sort the filter conditions
 */
static void __sort_filter_conds_fwd(sos_filter_t f)
{
	sos_attr_t filt_attr = sos_iter_attr(f->iter);
	struct sos_cond_list cond_list;
	struct sos_filter_cond_s *cond;

	TAILQ_INIT(&cond_list);
	while (!TAILQ_EMPTY(&f->cond_list)) {
		cond = TAILQ_FIRST(&f->cond_list);
		TAILQ_REMOVE(&f->cond_list, cond, entry);
		__insert_filter_cond_fwd(filt_attr, &cond_list, cond);
	}
	while (!TAILQ_EMPTY(&cond_list)) {
		cond = TAILQ_FIRST(&cond_list);
		TAILQ_REMOVE(&cond_list, cond, entry);
		TAILQ_INSERT_TAIL(&f->cond_list, cond, entry);
	}
}

static void __sort_filter_conds_bkwd(sos_filter_t f)
{
	sos_attr_t filt_attr = sos_iter_attr(f->iter);
	struct sos_cond_list cond_list;
	struct sos_filter_cond_s *cond;

	TAILQ_INIT(&cond_list);
	while (!TAILQ_EMPTY(&f->cond_list)) {
		cond = TAILQ_FIRST(&f->cond_list);
		TAILQ_REMOVE(&f->cond_list, cond, entry);
		__insert_filter_cond_bkwd(filt_attr, &cond_list, cond);
	}
	while (!TAILQ_EMPTY(&cond_list)) {
		cond = TAILQ_FIRST(&cond_list);
		TAILQ_REMOVE(&cond_list, cond, entry);
		TAILQ_INSERT_TAIL(&f->cond_list, cond, entry);
	}
}

/**
 * \brief Add a filter condition to the filter
 *
 * The filter conditions affect which objects are returned by
 * sos_filter_begin(), sos_filter_next(), etc...
 *
 * Logically, all filter conditions are ANDed together to get a
 * TRUE/FALSE answer when evaluating an object. If all filter
 * conditions match, the sos_filter_xxx() iterator functions will
 * return the object, otherwise, the next object in the index will be
 * evaluated until a match is found or all objects in the index are
 * exhausted.
 *
 * \param filt    The filter handle returned by sos_filter_new()
 * \param attr    The object attribute that will be evaluated by this condition
 * \param cond_e  One of the sos_cond_e comparison conditions
 * \param value   The value used in the expression "object-attribute-value cond_e value"
 * \retval 0      The condition was added successfully
 * \retval ENOMEM There was insufficient memory to allocate the filter condition
 */

int sos_filter_cond_add(sos_filter_t filt,
			sos_attr_t attr, enum sos_cond_e cond_e, sos_value_t value)
{
	sos_filter_cond_t cond = calloc(1, sizeof *cond);
	if (!cond)
		return ENOMEM;
	cond->attr = attr;
	cond->cmp_fn = fn_table[cond_e];
	cond->value = sos_value_copy(&cond->value_, value);
	cond->cond = cond_e;
	TAILQ_INSERT_TAIL(&filt->cond_list, cond, entry);
	return 0;
}

static sos_filter_cond_t sos_filter_eval(sos_obj_t obj, sos_filter_t filt)
{
	sos_filter_cond_t cond;
	struct sos_value_s v_;
	sos_value_t obj_value;
	int rc;
	TAILQ_FOREACH(cond, &filt->cond_list, entry) {
		obj_value = sos_value_init(&v_, obj, cond->attr);
		rc = cond->cmp_fn(obj_value, cond->value, &cond->ret);
		sos_value_put(obj_value);
		if (!rc)
			return cond;
	}
	sos_key_t key = sos_iter_key(filt->iter);
	sos_key_copy(filt->last_match, key);
	sos_key_put(key);
	return NULL;
}

/*
 * Searches for the next object that matches all of the conditions in
 * filt->cond_list. To avoid testing every object, conditions are sorted
 * and objects that can't match are skipped by building a key and searching
 * on the index.
 *
 * This table specifies how the key is constructed given the 1st
 * failing condition on an object.
 *
 * +==================+==================+==================+==================+
 * | obj-value ? key  |         <        |        ==        |         >        |
 * +==================I==================+==================+==================+
 * | condition   <    I         X        |    seek(max)     |    seek(max)     |
 * +------------------I------------------+------------------+------------------+
 * |             <=   I         X        |        X         |    seek(max)     |
 * +------------------I------------------+------------------+------------------+
 * |             ==   I seek(cond->value)|        X         |    seek(max)     |
 * +------------------I------------------+------------------+------------------+
 * |             >=   I seek(cond->value)|        X         |         X        |
 * +------------------I------------------+------------------+------------------+
 * |             >    I seek(cond->value)|      next        |         X        |
 * +------------------+------------------+------------------+------------------+
 *
 * The 'X' means "can't happen". The seek(min) sets the join key in
 * question to the minimum value for the value-type of the condition
 * attribute.
 *
 * seek(cond->value) means set the key to the value tested in the condition.
 */
static sos_obj_t next_match(sos_filter_t filt)
{
	SOS_KEY(key);
	int rc, i, join_idx;
	sos_obj_t obj;
	sos_filter_cond_t cond;
	sos_array_t attr_ids;
	struct sos_value_s v_;
	sos_value_t obj_value;
	ods_comp_key_t comp_key;
	ods_key_comp_t key_comp;
	size_t comp_len;
	sos_filter_cond_t join_cond;
	ods_ref_t last_ref = 0;

	filt->miss_cnt = 0;
	do {
		obj_value = NULL;
		obj = sos_iter_obj(filt->iter);
		if (!obj)
			break;
		cond = sos_filter_eval(obj, filt);
		if (!cond) {
			filt->empty = 0;
			return obj;
		}
		filt->miss_cnt += 1;
		/*
		 * One or more conditions failed, determine if there
		 * can be any subsequent key that matches all
		 * conditions given the index ordering.
		 */
		if (cond->cond == SOS_COND_NE)
			/* No ordering optimizations for NE */
			goto next;

		join_idx = __attr_join_idx(sos_iter_attr(filt->iter), cond->attr);
		if (join_idx < 0) {
			/*
			 * The filter key is not a join or the
			 * condition attribute is not in the join key
			 */
			if (cond->attr != filt->iter->attr)
				/*
				 * The filter index is not on
				 * condition attribute nothing can be
				 * assumed about the ordering
				 */
				goto next;
			if (cond->cond < SOS_COND_GE)
				/*
				 * The condition requires <=, this
				 * attribute is the key and the
				 * comparison failed. There can be no
				 * more matches
				 */
				break;
			/*
			 * Missing optimization to skip to 1st
			 * possibly matching key
			 */
			goto next;
		}

		if (sos_attr_is_array(cond->attr))
			goto next;

		/* Key = { k[0], k[1], ... k[join_idx], ..., k[N] }
		 *                              ^
		 *                              |
		 * Failing Condition :----------+
		 *
		 */

		if (join_idx == 0 || cond == TAILQ_FIRST(&filt->cond_list)) {
			if (join_idx)
				/* 1st condition skips join prefix, we know nothing */
				goto next;
			/*
			 * The failing condition was <, <= or ==. If the match
			 * was >, then there can not possibly be any more
			 * matches for this condition past this point in the
			 * index.
			 */
			if (cond->cond <= SOS_COND_GE) {
				if (cond->ret >= 0)
					break;

				/* Cond is <, <=, and key is smaller
				 * than value, keep searching.
				 */
			}
			/* Cond is >=, >, keep searching */
		}
		/*
		 * Construct a key putting max in the component
		 * key position associated with the failing condition
		 * and search for the least upper bound (i.e. next)
		 */
		comp_key = (ods_comp_key_t)ods_key_value(key);
		comp_key->len = 0;
		key_comp = comp_key->value;
		attr_ids = sos_attr_join_list(sos_iter_attr(filt->iter));

		for (i = 0; i < attr_ids->count; i++) {
			int attr_id = attr_ids->data.uint32_[i];
			obj_value = sos_value_by_id(&v_, obj, attr_id);
			join_cond = __sos_find_filter_condition(filt, attr_id);
			if (i < join_idx) {
				if (!join_cond)
					goto next;
				key_comp = __sos_set_key_comp(key_comp, obj_value, &comp_len);
			} else if (i == join_idx) {
				switch (cond->cond) {
				case SOS_COND_LT:
				case SOS_COND_LE:
					if (__sos_value_is_max(obj_value))
						goto next;
					key_comp = __sos_set_key_comp_to_max(key_comp, obj_value->attr, &comp_len);
					break;
				case SOS_COND_EQ:
					if (cond->ret < 0) {
						key_comp = __sos_set_key_comp(key_comp, cond->value, &comp_len);
					} else {
						if (__sos_value_is_max(obj_value))
							goto next;
						key_comp = __sos_set_key_comp_to_max(key_comp, obj_value->attr, &comp_len);
					}
					break;
				case SOS_COND_GE:
					key_comp = __sos_set_key_comp(key_comp, cond->value, &comp_len);
					break;
				case SOS_COND_GT:
					if (cond->ret < 0)
						key_comp = __sos_set_key_comp(key_comp, cond->value, &comp_len);
					else
						goto next;
					break;
				case SOS_COND_NE:
					goto next;
				}
			} else {
				if (sos_attr_is_array(obj_value->attr))
					goto next;
				key_comp = __sos_set_key_comp_to_min(key_comp, obj_value->attr, &comp_len);
			}
			sos_value_put(obj_value);
			comp_key->len += comp_len;
		}
		rc = sos_iter_sup(filt->iter, key);
		if (rc)
			break;
		if (last_ref == obj->obj->ref)
			goto out;
		last_ref = obj->obj->ref;
		sos_obj_put(obj);
		continue;
	next:
		sos_value_put(obj_value);
		rc = sos_iter_next(filt->iter);
		if (!rc)
			sos_obj_put(obj);
	} while (rc == 0);
 out:
	sos_obj_put(obj);
	filt->empty = 1;
	return NULL;
}

static sos_obj_t continue_next(sos_filter_t filt)
{
	int rc;
	SOS_KEY(key);
	__sort_filter_conds_fwd(filt);
	rc = __sos_filter_key_set(filt, key, 1, 1);
	switch (rc) {
	case 0:
		rc = sos_iter_begin(filt->iter);
		break;
	default:
		rc = sos_iter_sup(filt->iter, key);
		break;
	}
	/*
	 * The last_match key positions us at the last record we
	 * returned, skip it or the last record will keep getting
	 * returned
	 */
	rc = sos_iter_next(filt->iter);
	if (!rc)
		return next_match(filt);
	filt->empty = 1;
	return NULL;
}

/*
 * Searches for the previous object that matches all of the conditions in
 * filt->cond_list. To avoid testing every object, conditions are sorted
 * and objects that can't match are skipped by building a key and searching
 * on the index.
 *
 * This table specifies how the key is constructed given the 1st
 * failing condition on an object.
 *
 * +==================+==================+==================+==================+
 * | obj-value ? key  |         <        |        ==        |         >        |
 * +==================I==================+==================+==================+
 * | condition   <    I         X        |       prev       | seek(cond->value)|
 * +------------------I------------------+------------------+------------------+
 * |             <=   I         X        |        X         | seek(cond->value)|
 * +------------------I------------------+------------------+------------------+
 * |             ==   I    seek(min)     |        X         | seek(cond->value)|
 * +------------------I------------------+------------------+------------------+
 * |             >=   I    seek(min)     |        X         |         X        |
 * +------------------I------------------+------------------+------------------+
 * |             >    I    seek(min)     |    seek(min)     |         X        |
 * +------------------+------------------+------------------+------------------+
 *
 * The 'X' means "can't happen". The seek(min) sets the join key in
 * question to the minimum value for the value-type of the condition
 * attribute.
 *
 * Seek(cond->value) means set the key to the value tested in the condition.
 */
static sos_obj_t prev_match(sos_filter_t filt)
{
	SOS_KEY(key);
	int rc, i, join_idx;
	sos_obj_t obj;
	sos_filter_cond_t cond;
	sos_array_t attr_ids;
	struct sos_value_s v_;
	sos_value_t obj_value = NULL;
	ods_comp_key_t comp_key;
	ods_key_comp_t key_comp;
	size_t comp_len;
	sos_filter_cond_t join_cond;
	ods_ref_t last_ref = 0;
	do {
		obj = sos_iter_obj(filt->iter);
		if (!obj)
			break;
		cond = sos_filter_eval(obj, filt);
		if (!cond) {
			filt->empty = 0;
			return obj;
		}
		/*
		 * One or more conditions failed, determine if there
		 * can be any subsequent key that matches all
		 * conditions given the index ordering.
		 */
		if (cond->cond == SOS_COND_NE)
			/* No ordering optimizations for NE */
			goto prev;

		join_idx = __attr_join_idx(sos_iter_attr(filt->iter), cond->attr);
		if (join_idx < 0) {
			/*
			 * The filter key is not a join or the
			 * condition attribute is not in the join key
			 */
			if (cond->attr != filt->iter->attr)
				/*
				 * The filter index is not on
				 * condition attribute nothing can be
				 * assumed about the ordering
				 */
				goto prev;
			if (cond->cond > SOS_COND_EQ)
				/*
				 * The condition requires >=, this
				 * attribute is the key and the
				 * comparison failed. There can be no
				 * more matches
				 */
				break;
			goto prev;
		}

		if (join_idx == 0 || cond == TAILQ_FIRST(&filt->cond_list)) {
			if (join_idx)
				/* 1st condition skips join prefix, we know nothing */
				goto prev;
			/*
			 * The failing condition was ==, >=, or >. If
			 * the match was <, then there can not
			 * possibly be any more matches for this
			 * condition prior to this point in the index.
			 */
			if (cond->cond >= SOS_COND_EQ) {
				if (cond->ret <= 0)
					break;

				/* Cond is ==, >=,  or > and key is greater
				 * than value, keep searching.
				 */
				assert(0);
			}
			/* Cond is ==, <=, or < keep searching */
			goto prev;
		}

		if (sos_attr_is_array(cond->attr))
			goto prev;

		comp_key = (ods_comp_key_t)ods_key_value(key);
		comp_key->len = 0;
		key_comp = comp_key->value;
		attr_ids = sos_attr_join_list(sos_iter_attr(filt->iter));

		for (i = 0; i < attr_ids->count; i++) {
			int attr_id = attr_ids->data.uint32_[i];
			obj_value = sos_value_by_id(&v_, obj, attr_id);
			join_cond = __sos_find_filter_condition(filt, attr_id);
			if (i < join_idx) {
				if (!join_cond)
					goto prev;
				key_comp = __sos_set_key_comp(key_comp, obj_value, &comp_len);
			} else if (i == join_idx) {
				switch (cond->cond) {
				case SOS_COND_LT:
				case SOS_COND_LE:
					if (cond->ret > 0)
						key_comp = __sos_set_key_comp(key_comp, cond->value, &comp_len);
					else
						goto prev;
					break;
				case SOS_COND_EQ:
					if (cond->ret < 0) {
						key_comp = __sos_set_key_comp(key_comp, cond->value, &comp_len);
					} else {
						if (__sos_value_is_min(obj_value))
							goto prev;
						key_comp = __sos_set_key_comp_to_min(key_comp, obj_value->attr, &comp_len);
					}
					break;
				case SOS_COND_GE:
				case SOS_COND_GT:
					if (__sos_value_is_min(obj_value))
						goto prev;
					key_comp = __sos_set_key_comp_to_min(key_comp, obj_value->attr, &comp_len);
					break;
				case SOS_COND_NE:
					goto prev;
				}
			} else {
				if (sos_attr_is_array(obj_value->attr))
					goto prev;
				key_comp = __sos_set_key_comp_to_max(key_comp, obj_value->attr, &comp_len);
			}
			sos_value_put(obj_value);
			comp_key->len += comp_len;
		}
		rc = sos_iter_inf(filt->iter, key);
		if (rc)
			break;
		if (last_ref == obj->obj->ref)
			goto out;
		last_ref = obj->obj->ref;
		sos_obj_put(obj);
		continue;
	prev:
		sos_value_put(obj_value);
		rc = sos_iter_prev(filt->iter);
		if (!rc)
			sos_obj_put(obj);
	} while (rc == 0);

 out:
	sos_obj_put(obj);
	filt->empty = 1;
	return NULL;
}

static sos_obj_t continue_prev(sos_filter_t filt)
{
	int rc;
	SOS_KEY(key);

	__sort_filter_conds_bkwd(filt);
	rc = __sos_filter_key_set(filt, key, 0, 1);
	switch (rc) {
	case 0:
		rc = sos_iter_end(filt->iter);
		break;
	case ESRCH:
		rc = sos_iter_inf(filt->iter, key);
		break;
	default:
		errno = rc;
		return NULL;
	}
	if (!rc)
		return prev_match(filt);
	filt->empty = 1;
	return NULL;
}

static sos_filter_cond_t __sos_find_filter_condition(sos_filter_t filt, int attr_id)
{
	sos_filter_cond_t cond;
	TAILQ_FOREACH(cond, &filt->cond_list, entry) {
		if (attr_id == sos_attr_id(cond->attr))
			return cond;
	}
	return NULL;
}

static int __sos_filter_key_set(sos_filter_t filt, sos_key_t key, int min_not_max, int last_match)
{
	sos_filter_cond_t cond;
	int join_idx;
	sos_attr_t filt_attr = sos_iter_attr(filt->iter);
	int filt_attr_id = sos_attr_id(filt_attr);
	int search = 0;
	sos_array_t attr_ids = sos_attr_join_list(filt_attr);

	if (last_match) {
		sos_key_copy(key, filt->last_match);
		return ESRCH;
	}

	if (sos_attr_type(filt_attr) != SOS_TYPE_JOIN) {
		/* Find the first condition that matches the filter attr */
		cond = __sos_find_filter_condition(filt, filt_attr_id);
		if (!cond)
			goto out;
		sos_key_set(key, sos_value_as_key(cond->value),
			    sos_value_size(cond->value));
		if (cond->cond != SOS_COND_NE && (cond->cond >= SOS_COND_EQ))
			search = ESRCH;
	} else {
		ods_comp_key_t comp_key;
		ods_key_comp_t key_comp;
		comp_key = (ods_comp_key_t)ods_key_value(key);
		key_comp = comp_key->value;
		comp_key->len = 0;
		for (join_idx = 0; join_idx < attr_ids->count; join_idx++) {
			int join_attr_id = attr_ids->data.uint32_[join_idx];
			size_t comp_len;
			/* Search the condition list for this attribute */
			cond = __sos_find_filter_condition(filt, join_attr_id);

			if (cond) {
				if (sos_attr_is_array(cond->attr)) {
					key_comp = __sos_set_key_comp(key_comp, cond->value, &comp_len);
				} else if (min_not_max) {
					switch (cond->cond) {
					case SOS_COND_LT:
					case SOS_COND_NE:
					case SOS_COND_LE:
						key_comp = __sos_set_key_comp_to_min(key_comp, cond->attr, &comp_len);
						search = ESRCH;
						break;
					case SOS_COND_EQ:
					case SOS_COND_GE:
					case SOS_COND_GT:
						key_comp = __sos_set_key_comp(key_comp, cond->value, &comp_len);
						search = ESRCH;
						break;
					}
				} else {
					switch (cond->cond) {
					case SOS_COND_LT:
					case SOS_COND_LE:
					case SOS_COND_EQ:
						key_comp = __sos_set_key_comp(key_comp, cond->value, &comp_len);
						search = ESRCH;
						break;
					case SOS_COND_NE:
					case SOS_COND_GE:
					case SOS_COND_GT:
						key_comp = __sos_set_key_comp_to_max(key_comp, cond->attr, &comp_len);
						search = ESRCH;
						break;
					}
				}
				comp_key->len += comp_len;
			} else {
				sos_attr_t attr;
				/*
				 * If there is no condition on the prefix,
				 * don't bother with a search
				 */
				if (!join_idx)
					goto out;
				attr = sos_schema_attr_by_id(sos_attr_schema(filt_attr),
							     join_attr_id);
				if (sos_attr_is_array(attr) || sos_attr_is_ref(attr)) {
					/* There is no condition for this key component and the
					 * attribute has a variable length. The key order after the
					 * previous components will be determined by length.
					 */
					goto out;
				}
				if (min_not_max) {
					key_comp = __sos_set_key_comp_to_min(key_comp, attr, &comp_len);
				} else {
					key_comp = __sos_set_key_comp_to_max(key_comp, attr, &comp_len);
				}
				search = ESRCH;
				comp_key->len += comp_len;
			}
		}
	}
 out:
	return search;
}

/**
 * \brief Return the miss-compare count
 *
 * A miss-compare is an object on the iterator that was skipped due to
 * a failure to match all conditions on the filter. This value can be
 * useful when tuning queries for performance.
 *
 * \returns The miss count
 */
int sos_filter_miss_count(sos_filter_t filt)
{
	return filt->miss_cnt;
}


/**
 * \brief Return the first matching object.
 *
 * \param filt The filter handle.
 * \retval !NULL Pointer to the matching sos_obj_t.
 * \retval NULL  No object's matched all of the filter conditions.
 */
sos_obj_t sos_filter_begin(sos_filter_t filt)
{
	int rc;
	SOS_KEY(key);

	__sort_filter_conds_fwd(filt);
	rc = __sos_filter_key_set(filt, key, 1, 0);
	switch (rc) {
	case 0:
		rc = sos_iter_begin(filt->iter);
		break;
	default:
		rc = sos_iter_sup(filt->iter, key);
		break;
	}
	if (!rc)
		return next_match(filt);
	return NULL;
}

/**
 * \brief Return the next matching object.
 *
 * \param filt The filter handle.
 * \retval !NULL Pointer to the matching sos_obj_t.
 * \retval NULL  No object's matched all of the filter conditions.
 */
sos_obj_t sos_filter_next(sos_filter_t filt)
{
	if (filt->empty)
		return continue_next(filt);
	if (0 == sos_iter_next(filt->iter))
		return next_match(filt);
	filt->empty = 1;
	return NULL;
}

int sos_filter_pos_set(sos_filter_t filt, const sos_pos_t pos)
{
	return sos_iter_pos_set(filt->iter, pos);
}

int sos_filter_pos_get(sos_filter_t filt, sos_pos_t *pos)
{
	return sos_iter_pos_get(filt->iter, pos);
}

int sos_filter_pos_put(sos_filter_t filt, sos_pos_t pos)
{
	return sos_iter_pos_put(filt->iter, pos);
}

sos_obj_t sos_filter_prev(sos_filter_t filt)
{
	if (filt->empty)
		return continue_prev(filt);
	if (0 == sos_iter_prev(filt->iter));
		return prev_match(filt);
	filt->empty = 1;
	return NULL;
}

sos_obj_t sos_filter_end(sos_filter_t filt)
{
	int rc;
	SOS_KEY(key);

	__sort_filter_conds_bkwd(filt);
	rc = __sos_filter_key_set(filt, key, 0, 0);
	switch (rc) {
	case 0:
		rc = sos_iter_end(filt->iter);
		break;
	default:
		rc = sos_iter_inf(filt->iter, key);
		break;
	}
	if (!rc)
		return prev_match(filt);
	return NULL;
}

sos_obj_t sos_filter_obj(sos_filter_t filt)
{
	return sos_iter_obj(filt->iter);
}

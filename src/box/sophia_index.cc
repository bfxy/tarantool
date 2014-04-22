/*
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 * 1. Redistributions of source code must retain the above
 *    copyright notice, this list of conditions and the
 *    following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY <COPYRIGHT HOLDER> ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * <COPYRIGHT HOLDER> OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include "sophia_index.h"
#include "say.h"
#include "tuple.h"
#include "pickle.h"
#include "scoped_guard.h"
#include "exception.h"
#include "errinj.h"

#include "schema.h"
#include "space.h"

#include <sophia.h>
#include <stdio.h>

static inline int
sophia_index_compare(char *a, size_t asz __attribute__((unused)),
                     char *b, size_t bsz __attribute__((unused)),
                     void *arg)
{
	struct key_def *key_def = (struct key_def*)arg;

	int rc = tuple_compare_field(a, b, key_def->parts[0].type);
	return (rc == 0) ? 0 :
	       ((rc > 0) ? 1 : -1);
}

static struct tuple *
sophia_gettuple(void *db, const char *key, size_t keysize)
{
	size_t valuesize = 0;
	char *value = NULL;
	int rc = sp_get(db, key, keysize, (void**)&value, &valuesize);
	if (rc == -1)
		tnt_raise(ClientError, ER_SOPHIA, sp_error(db));
	if (rc == 0)
		return NULL;
	auto scoped_guard = make_scoped_guard([=] { free(value); });
	struct tuple *ret =
		tuple_new(tuple_format_ber, value, value + valuesize);
	tuple_ref(ret, 1);
	return ret;
}

/* {{{ SophiaIndex */

SophiaIndex::SophiaIndex(struct key_def *key_def_arg __attribute__((unused)))
	: Index(key_def_arg)
{
	env = sp_env();
	if (env == NULL)
		tnt_raise(ClientError, ER_MEMORY_ISSUE, sizeof(void*),
			  "SophiaIndex", "env");

	auto env_freer =
		make_scoped_guard([=] { sp_destroy(env); });

	int rc = sp_ctl(env, SPCMP, sophia_index_compare, key_def);
	if (rc == -1)
		tnt_raise(ClientError, ER_SOPHIA, sp_error(env));

	char path[PATH_MAX];
	snprintf(path, sizeof(path), "sophia/%04d", key_def->space_id);
	rc = sp_ctl(env, SPDIR, SPO_RDWR|SPO_CREAT, path);
	if (rc == -1)
		tnt_raise(ClientError, ER_SOPHIA, sp_error(env));

	say_info("start sophia space '%s' recover", path);

	db = sp_open(env);
	if (db == NULL)
		tnt_raise(ClientError, ER_SOPHIA, sp_error(env));

	say_info("recover complete");

	env_freer.is_active = false;
}

SophiaIndex::~SophiaIndex()
{
	if (m_position != NULL) {
		m_position->free(m_position);
		m_position = NULL;
	}

	if (db) {
		int rc = sp_destroy(db);
		if (rc == -1)
			say_info("sophia space %d close error: %s", key_def->space_id,
			         sp_error(env));
	}
	if (env) {
		sp_destroy(env);
	}
}

void
SophiaIndex::endBuild()
{
}

size_t
SophiaIndex::size() const
{
	return 0;
}

size_t
SophiaIndex::memsize() const
{
	return 0;
}

struct tuple *
SophiaIndex::findByKey(const char *key, uint32_t part_count) const
{
	(void) part_count;
	assert(part_count == 1);
	assert(key_def->is_unique && part_count == key_def->part_count);
	const char *keyptr = key;
	mp_next(&keyptr);
	size_t keysize = keyptr - key;
	struct tuple *ret = sophia_gettuple(db, key, keysize);
	return ret;
}

static inline uint32_t
sophia_check_dup(struct key_def *key_def,
                 struct tuple *old_tuple,
                 struct tuple *dup_tuple, enum dup_replace_mode mode)
{
	if (dup_tuple == NULL) {
		if (mode == DUP_REPLACE) {
			/*
			 * dup_replace_mode is DUP_REPLACE, and
			 * a tuple with the same key is not found.
			 */
			return ER_TUPLE_NOT_FOUND;
		}
	} else { /* dup_tuple != NULL */

		int equal = old_tuple != NULL &&
			tuple_compare(dup_tuple, old_tuple, key_def) == 0;

		if (!equal && (old_tuple != NULL || mode == DUP_INSERT)) {
			/*
			 * There is a duplicate of new_tuple,
			 * and it's not old_tuple: we can't
			 * possibly delete more than one tuple
			 * at once.
			 */
			return ER_TUPLE_FOUND;
		}
	}
	return 0;
}

struct tuple *
SophiaIndex::replace(struct tuple *old_tuple, struct tuple *new_tuple,
		   enum dup_replace_mode mode)
{
	if (new_tuple) {
		assert(new_tuple->refs == 0);

		const char *key = tuple_field(new_tuple, key_def->parts[0].fieldno);
		const char *keyptr = key;
		mp_next(&keyptr);
		size_t keysize = keyptr - key;

		struct tuple *dup_tuple = sophia_gettuple(db, key, keysize);

		uint32_t errcode =
			sophia_check_dup(key_def, old_tuple, dup_tuple, mode);
		if (errcode) {
			if (dup_tuple)
				tuple_ref(dup_tuple, -1);
			tnt_raise(ClientError, errcode, index_id(this));
		}

		int rc = sp_set(db, key, keysize, new_tuple->data, new_tuple->bsize);
		if (rc == -1) {
			if (dup_tuple)
				tuple_ref(dup_tuple, -1);
			tnt_raise(ClientError, ER_SOPHIA, sp_error(db));
		}

		if (dup_tuple)
			return dup_tuple;
	}

	if (old_tuple) {
		/* delete */
		const char *key = tuple_field(old_tuple, key_def->parts[0].fieldno);
		const char *keyptr = key;
		mp_next(&keyptr);
		size_t keysize = keyptr - key;
		int rc = sp_delete(db, key, keysize);
		if (rc == -1)
			tnt_raise(ClientError, ER_SOPHIA, sp_error(db));
	}

	return old_tuple;
}

struct sophia_iterator {
	struct iterator base;
	const char *key;
	int keysize;
	uint32_t part_count;
	void *db;
	void *cursor;
};

void
sophia_iterator_free(struct iterator *ptr)
{
	assert(ptr->free == sophia_iterator_free);
	struct sophia_iterator *it = (struct sophia_iterator *) ptr;
	if (it->cursor)
		sp_destroy(it->cursor);
	free(ptr);
}

void
sophia_iterator_close(struct iterator *ptr)
{
	assert(ptr->free == sophia_iterator_free);
	struct sophia_iterator *it = (struct sophia_iterator *) ptr;
	if (it->cursor) {
		sp_destroy(it->cursor);
		it->cursor = NULL;
	}
}

struct tuple *
sophia_iterator_next(struct iterator *ptr)
{
	assert(ptr->next == sophia_iterator_next);
	struct sophia_iterator *it = (struct sophia_iterator *) ptr;
	assert(it->cursor != NULL);
	int rc = sp_fetch(it->cursor);
	if (rc == 0)
		return NULL;
	size_t valuesize = sp_valuesize(it->cursor);
	const char *value = sp_value(it->cursor);
	struct tuple *ret =
		tuple_new(tuple_format_ber, value, value + valuesize);
	tuple_ref(ret, 1);
	return ret;
}

struct tuple *
sophia_iterator_last(struct iterator *ptr __attribute__((unused)))
{
	return NULL;
}

struct tuple *
sophia_iterator_eq(struct iterator *ptr)
{
	ptr->next = sophia_iterator_last;
	struct sophia_iterator *it = (struct sophia_iterator *) ptr;
	assert(it->cursor == NULL);
	return sophia_gettuple(it->db, it->key, it->keysize);
}

struct iterator *
SophiaIndex::allocIterator() const
{
	struct sophia_iterator *it =
		(struct sophia_iterator *) calloc(1, sizeof(*it));
	if (it == NULL) {
		tnt_raise(ClientError, ER_MEMORY_ISSUE,
		          sizeof(struct sophia_iterator), "SophiaIndex",
		          "iterator");
	}
	it->base.next  = sophia_iterator_next;
	it->base.close = sophia_iterator_close;
	it->base.free  = sophia_iterator_free;
	it->cursor = NULL;
	return (struct iterator *) it;
}

void
SophiaIndex::initIterator(struct iterator *ptr, enum iterator_type type,
		const char *key, uint32_t part_count) const
{
	assert(part_count <= 1);

	struct sophia_iterator *it = (struct sophia_iterator *) ptr;
	assert(it->cursor == NULL);

	size_t keysize;
	if (part_count > 0) {
		const char *keyptr = key;
		mp_next(&keyptr);
		keysize = keyptr - key;
	} else {
		keysize = 0;
		key = NULL;
	}
	it->key = key;
	it->keysize = keysize;
	it->part_count = part_count;
	it->db = db;

	sporder compare;
	switch (type) {
	case ITER_EQ: it->base.next = sophia_iterator_eq;
		return;
	case ITER_ALL:
	case ITER_GE: compare = SPGTE;
		break;
	case ITER_GT: compare = SPGT;
		break;
	case ITER_LE: compare = SPLTE;
		break;
	case ITER_LT: compare = SPLT;
		break;
	default:
		tnt_raise(ClientError, ER_UNSUPPORTED,
		          "SophiaIndex", "requested iterator type");
	}
	it->cursor = sp_cursor(db, compare, key, keysize);
	if (it->cursor == NULL)
		tnt_raise(ClientError, ER_SOPHIA, sp_error(db));
}

/* }}} */

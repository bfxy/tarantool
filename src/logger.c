/*
 * Copyright 2010-2015, Tarantool AUTHORS, please see AUTHORS file.
 *
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
#include "logger.h"
#include "tt_pthread.h"
#include "third_party/pmatomic.h"
#include <unistd.h>
#include <fcntl.h>

/**
 * Public logger api
 */

void logger_write_message(char *buf, size_t buf_size,
                          const struct logger_message *m)
{
	struct logger *l = logger_acquire();
	assert(l);
	assert(l->write_message);
	l->write_message(l, buf, buf_size, m);
	logger_release(l);
}

void logger_redirect_stdout_stderr()
{
	int fd = -1, devnull_fd = -1;
	struct logger *l = logger_acquire();
	assert(l);
	if (l->get_fd)
		fd = l->get_fd(l);
	if (fd == -1) {
		devnull_fd = open("/dev/null", O_WRONLY|O_CLOEXEC|O_NONBLOCK);
		fd = devnull_fd;
	}
	if (fd != -1) {
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
	}
	logger_release(l);
	if (devnull_fd != -1)
		close(devnull_fd);
}

void logger_logrotate()
{
	struct logger *l = logger_acquire();
	assert(l);
	if (l->logrotate)
		l->logrotate(l);
	logger_release(l);
}

void logger_sig_logrotate(int sig)
{
	(void)sig;
	struct logger *l = logger_sig_acquire();
	assert(l);
	if (l->sig_logrotate)
		l->sig_logrotate(l);
	logger_sig_release(l);
}

pid_t logger_get_helper_pid()
{
	pid_t pid = -1;
	struct logger *l = logger_acquire();
	assert(l);
	if (l->get_helper_pid)
		pid = l->get_helper_pid(l);
	logger_release(l);
	return pid;
}

/**
 * Install-acquire-release operations.
 *
 * The installed logger is tracked in the global 'registration'
 * structure.  All fields are squeezed into a pointer-sized variable
 * allowing for atomic operations affecting several fields:
 *
 *   - slotno             index in the auxiliary pointer array,
 *                        LOGGER_SLOTNO_DEFAULT if no logger was
 *                        installed; using indirection instead of
 *                        a raw logger pointer to save bits;
 *   - lock_counter       used for locking;
 *   - reference_counter  refcount of the current logger.
 *
 * Note: fields are arranged in such a way that the overflowing
 * reference counter doesn't corrupt other fields.
 *
 * Operations breakdown follows. Notation: {{ ... }} designates a sequence
 * of operations executing atomically.
 *
 * logger_sig_acquire():
 *     {{ lock_counter++; result <- slots[slotno] }}
 *
 * logger_sig_release(l):
 *     {{ lock_counter-- }}
 *
 * logger_install(l):
 *     new_slotno <- allocate_slot(l)
 *     while not SUCCESS: {{
 *             if lock_counter != 0: FAIL
 *             old_slotno <- slotno
 *             old_reference_counter <- reference_counter
 *             slotno <- new_slotno
 *             reference_counter <- 0
 *         }}
 *     if old_slotno == LOGGER_SLOTNO_DEFAULT: return
 *     // transfer reference count
 *     {{
 *         slots[old_slotno]->refcount += old_reference_counter
 *         need_teardown <- (slots[old_slotno]->refcount == 0)
 *     }}
 *     if need_teardown: teardown(slots[old_slotno])
 *
 * logger_acquire():
 *     {{ reference_counter++; result <- slots[slotno] }}
 *
 * logger_release(l):
 *     if l == &default_loggger: return
 *     {{
 *        if slotno == l->slotno:
 *            reference_counter--
 *        else:
 *            logger_swapped <- true
 *     }}
 *     if logger_swapped: {{
 *        l->refcount--
 *        need_teardown <- (l->refcount == 0)
 *     }}
 *     if need_teardown: teardown(l)
 *
 *
 * Note 1: lock_counter and reference_counter are both 11 bits wide,
 *         overflow is fatal (we check for it), should not happen (C)
 *
 * Note 2: logger_release() never decrements reference_counter when
 *         releasing the default logger. This leads to the
 *         reference_counter overflowing eventually. In this particular
 *         situatuation it is fine (logger_install() ignores the
 *         counter when replacing the default logger; other fields
 *         aren't corrupted due to the registration layout).
 *
 * Note 3: interleaved execution of install/release operations may
 *         result in the object's refcount going below zero if release
 *         completes before install have transfered the reference count,
 *         this is fine.
 *
 * Note 4: once allocated, the slotno is valid until the logger
 *         teardown. This prevents ABA problem in logger_release().
 */
enum {
	LOGGER_SLOTS_NUM = 4,

	/* slotno */
	LOGGER_SLOTNO_BITS = 8,
	LOGGER_SLOTNO_DEFAULT = (1 << LOGGER_SLOTNO_BITS) - 1,

	/* lock_counter, guard bit for overflow detection  */
	LOGGER_LOCK_COUNTER_BIT_OFFSET = LOGGER_SLOTNO_BITS,
	LOGGER_LOCK_COUNTER_BITS = 11,
	LOGGER_LOCK_COUNTER_MAX = (1 << LOGGER_LOCK_COUNTER_BITS) - 1,
	LOGGER_LOCK_COUNTER_GUARD_BITS = 1,
	LOGGER_LOCK_COUNTER_INCREMENT =
		(1 << LOGGER_LOCK_COUNTER_BIT_OFFSET),

	/* ref_counter, gurad bit for overflow detection */
	LOGGER_REF_COUNTER_BIT_OFFSET =
		LOGGER_LOCK_COUNTER_BIT_OFFSET + LOGGER_LOCK_COUNTER_BITS +
		LOGGER_LOCK_COUNTER_GUARD_BITS,
	LOGGER_REF_COUNTER_BITS = 11,
	LOGGER_REF_COUNTER_MAX = (1 << LOGGER_REF_COUNTER_BITS) - 1,
	LOGGER_REF_COUNTER_GUARD_BITS = 1,
	LOGGER_REF_COUNTER_INCREMENT =
		(1 << LOGGER_REF_COUNTER_BIT_OFFSET),
};
typedef uint32_t logger_reg_t;
static logger_reg_t logger_registration = 0;

/**
 * Routines for field extraction from a logger registration
 */
static inline int
logger_registration_get_slotno(logger_reg_t reg)
{
	return reg & (((logger_reg_t)1 << LOGGER_SLOTNO_BITS) - 1);
}

static inline int
logger_registration_get_lock_counter(logger_reg_t reg)
{
	return (reg >> LOGGER_LOCK_COUNTER_BIT_OFFSET) &
		(((logger_reg_t)1 << LOGGER_LOCK_COUNTER_BITS) - 1);
}

static inline int
logger_registration_get_ref_counter(logger_reg_t reg)
{
	return (reg >> LOGGER_REF_COUNTER_BIT_OFFSET) &
		(((logger_reg_t)1 << LOGGER_REF_COUNTER_BITS) - 1);
}

static inline logger_reg_t
logger_registration_from_slotno(int slotno)
{
	return slotno;
}

/** logger_slots: auxiliary pointer array, protected with mutex */
static pthread_mutex_t logger_slots_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t logger_slots_cond = PTHREAD_COND_INITIALIZER;
static struct logger *logger_slots[LOGGER_SLOTS_NUM];

static void logger_teardown(struct logger *l)
{
	assert(l != &default_logger);
	assert(l->slotno >= 0 && l->slotno < LOGGER_SLOTS_NUM);
	tt_pthread_mutex_lock(&logger_slots_mutex);
	assert(logger_slots[l->slotno] == l);
	logger_slots[l->slotno] = NULL;
	tt_pthread_cond_signal(&logger_slots_cond);
	tt_pthread_mutex_unlock(&logger_slots_mutex);
	if (l->teardown)
		l->teardown(l);
}

void logger_install(struct logger *l)
{
	assert(l != &default_logger);

	int slotno = LOGGER_SLOTNO_DEFAULT;

	if (l) {
		/* Assign a slot */
		int i;
		tt_pthread_mutex_lock(&logger_slots_mutex);
	rescan:
		for (i = 0; i < LOGGER_SLOTS_NUM; i++) {
			if (logger_slots[i] == NULL) {
				logger_slots[i] = l;
				slotno = l->slotno = i;
				goto have_slot;
			}
		}
		/*
		 * Spare slot not found. Wait until a slot becomes available,
		 * logger_teardown() will signal the condition.
		 * Note: a slot is assigned when the logger is installed.
		 * A slot is reclaimed when the last reference to the logger is
		 * logger_release()-d, this design is necessary to avoid ABA
		 * problem.
		 * Running out of slots due to multiple lingering logger objects
		 * is extremely unlikely.
		 */
		tt_pthread_cond_wait(&logger_slots_cond, &logger_slots_mutex);
		goto rescan;
	have_slot:
		tt_pthread_mutex_unlock(&logger_slots_mutex);
		l->refcount = 0;
	}

	logger_reg_t new_reg = logger_registration_from_slotno(slotno);
	logger_reg_t prev_reg;
	while (true) {
		/* Swap logger registrations if not locked (atomically) */
		prev_reg = pm_atomic_load(&logger_registration);
		if (logger_registration_get_lock_counter(prev_reg) == 0 &&
		    pm_atomic_compare_exchange_weak(&logger_registration, &prev_reg,
				                            new_reg))
			break;
	}

	int prev_slotno = logger_registration_get_slotno(prev_reg);
	if (prev_slotno == LOGGER_SLOTNO_DEFAULT)
		return;

	assert(prev_slotno >= 0 && prev_slotno < LOGGER_SLOTS_NUM);
	struct logger *prev_l = logger_slots[prev_slotno];
	assert(prev_l);
	assert(prev_l != l);
	assert(prev_l->slotno == prev_slotno);

	/* Transfer reference count.
	 * Note: increasing refcount in prev_l; this may still result in
	 * refcount reaching zero if it mas negative due to interleaved
	 * execution of logger_release().
	 */
	int prev_refcount = logger_registration_get_ref_counter(prev_reg);
	if (pm_atomic_fetch_add(&prev_l->refcount,
	                        prev_refcount) == -prev_refcount)
		logger_teardown(prev_l);
}

struct logger *logger_acquire()
{
	logger_reg_t cur_reg;

	/* Increment reference counter, capture logger reference. */
	cur_reg = pm_atomic_fetch_add(&logger_registration,
		                          LOGGER_REF_COUNTER_INCREMENT);

	int slotno = logger_registration_get_slotno(cur_reg);

	/* Default logger installed?  In this particular case we leave
	 * reference counter in inconsistent state. This is perfectly fine
	 * because
	 *   a) we carefully ignore refcount in logger_* routines if the
	 *      default logger is installed;
	 *   b) registration layout is designed in such a way that
	 *      overflowing reference counter doesn't corrupt other
	 *      fields;
	 *   c) fixing the reference counter is hard due to ABA problem.
	 */
	if (slotno == LOGGER_SLOTNO_DEFAULT)
		return &default_logger;

	/* Check for refcount overflow. */
	if (logger_registration_get_ref_counter(cur_reg) >=
		LOGGER_REF_COUNTER_MAX)
	{
		abort();
	}

	assert(slotno >= 0 && slotno < LOGGER_SLOTS_NUM);
	assert(logger_slots[slotno]);
	assert(logger_slots[slotno]->slotno == slotno);

	return logger_slots[slotno];
}

void logger_release(struct logger *l)
{
	assert(l);
	if (l == &default_logger)
		return;

	int slotno = l->slotno;
	assert(slotno >= 0 && slotno < LOGGER_SLOTS_NUM);
	assert(logger_slots[slotno] == l);

	while (true) {
		logger_reg_t cur_reg = pm_atomic_load(&logger_registration);

		/* A different logger was installed meanwhile? */
		if (logger_registration_get_slotno(cur_reg) != slotno)
			break;

		assert(logger_registration_get_ref_counter(cur_reg) != 0);

		/* Same logger; update inline reference counter. */
		logger_reg_t upd_reg = cur_reg - LOGGER_REF_COUNTER_INCREMENT;
		if (pm_atomic_compare_exchange_weak(&logger_registration,
		                                    &cur_reg, upd_reg))
			return;
	}

	/* The logger was swapped, reference counter transfered to
	 * l->refcount, update. If logger_install() executes concurrently
	 * and l->refcount is yet to be updated it may become negative after
	 * fetch_add, this is fine. */
	if (pm_atomic_fetch_add(&l->refcount, -1) == 1)
		logger_teardown(l);
}

struct logger *logger_sig_acquire()
{
	logger_reg_t cur_reg;

	/* Increment lock counter. */
	cur_reg = pm_atomic_fetch_add(&logger_registration,
	                              LOGGER_LOCK_COUNTER_INCREMENT);

	/* Check for lock counter overflow. */
	if (logger_registration_get_lock_counter(cur_reg) >=
	    LOGGER_LOCK_COUNTER_MAX)
	{
		abort();
	}

	int slotno = logger_registration_get_slotno(cur_reg);
	if (slotno == LOGGER_SLOTNO_DEFAULT)
		return &default_logger;

	assert(slotno >= 0 && slotno < LOGGER_SLOTS_NUM);
	assert(logger_slots[slotno]);
	assert(logger_slots[slotno]->slotno == slotno);

	return logger_slots[slotno];
}

void logger_sig_release(struct logger *l)
{
	logger_reg_t cur_reg, delta = LOGGER_LOCK_COUNTER_INCREMENT;

	/* Decrement lock counter. */
	cur_reg = pm_atomic_fetch_add(&logger_registration, -delta);

	int slotno = logger_registration_get_slotno(cur_reg);
	(void)slotno;

	assert(l);
	assert(logger_registration_get_lock_counter(cur_reg) != 0);
	assert((slotno == LOGGER_SLOTNO_DEFAULT && l == &default_logger) ||
           slotno == l->slotno);
}


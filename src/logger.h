#ifndef TARANTOOL_LOGGER_H_INCLUDED
#define TARANTOOL_LOGGER_H_INCLUDED
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

/**
 * A simple pluggable framework allowing for modular log destinations.
 * The core feature are the lightweight install-acquire-release
 * operations allowing to install and access the global logger in a
 * thread- and signal-safe manner.
 * Though logically the logger is a singleton object when it is being
 * replaced a transitional state is possible when multiple loggers are
 * in use simultaneously due to ex. some thread not yet released its
 * reference to the old logger.
 * Hence the OO aproach not only provides for a better code structure;
 * it allows for efficient and lightweight install-acquire-release
 * operations. This approach generally allows to avoid locking in the
 * logger object as well. The logger is fully initialized before being
 * installed; and after it has been initialized the state virtually
 * doesn't change any more (RCU-style updates).
 */
#include <stdarg.h>
#include <stdbool.h>
#include <sys/types.h> /* pid_t */

#if defined(__cplusplus)
extern "C" {
#endif /* defined(__cplusplus) */

struct logger;
struct logger_message;

void logger_create_file(const char *path, bool nonblock);

void logger_create_pipe(const char *command, bool nonblock);

void logger_create_syslog(const char *identity, int facility);

/** Write a message to the log */
void logger_write_message(char *buf, size_t buf_size,
                          const struct logger_message *);

/**
 * Duplicate logger fd and use it for stdout and stderr.
 * If no fd is available, use /dev/null.
 */
void logger_redirect_stdout_stderr();

/** Perform log rotation, if implemented. */
void logger_logrotate();

/** logrotate() flavour for use in a signal handler. */
void logger_sig_logrotate(int sig);

/** Get helper process pid, if any. */
pid_t logger_get_helper_pid();

extern struct logger default_logger;

struct logger {
	/* Private to logger framework */
	int32_t refcount;
	int32_t slotno;
	/* vtable */
	void  (*write_message) (struct logger *,
	                        char *buf, size_t buf_size,
	                        const struct logger_message *);
	void  (*teardown) (struct logger *);
	void  (*logrotate) (struct logger *);
	void  (*sig_logrotate) (struct logger *); /* This one is called
	                                             from a signal handler */
	int   (*get_fd) (struct logger *);
	pid_t (*get_helper_pid) (struct logger *);
};

struct logger_message {
	int level;
	const char *filename;
	int line;
	const char *error;
	const char *format;
	va_list ap;
};

/** Semi-private api. ************************************************/

/**
 * Install a logger. Destroys the previously installed logger, if any.
 *
 * Note: the installed logger will be accessed concurrently, all
 * necessary memory barriers included in logger_install().
 */
void logger_install(struct logger *l);

/**
 * Acquire a logger; must be paired with logger_release().
 *
 * Returns the installed logger if available (see logger_install) or the
 * default one.
 *
 * The returned object is guaranteed to live until the matching
 * logger_release().
 *
 * No mutual exclusion provided: threads may acquire the same logger
 * concurrently.
 */
static struct logger *logger_acquire();

/**
 * Release a formerly acquired logger, may trigger logger teardown.
 */
static void logger_release(struct logger *l);

/**
 * logger_acquire() flavour for use in a signal handler.
 */
static struct logger *logger_sig_acquire();

/**
 * logger_release() flavour for use in a signal handler.
 */
static void logger_sig_release(struct logger *l);

#if defined(__cplusplus)
} /* extern "C" */
#endif /* defined(__cplusplus) */

#endif /* TARANTOOL_LOGGER_H_INCLUDED */

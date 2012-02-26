/*
 * Copyright (C) 2011 Julien Desfossez
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License Version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _GNU_SOURCE
#include <config.h>
#include <stdio.h>
#include <stdint.h>
#include <babeltrace/babeltrace.h>
#include <babeltrace/ctf/events.h>
#include <babeltrace/ctf/callbacks.h>
#include <fcntl.h>
#include <pthread.h>
#include <popt.h>
#include <stdlib.h>
#include <ftw.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <fts.h>
#include <assert.h>

#include "lttngtoptypes.h"
#include "cputop.h"
#include "iostreamtop.h"
#include "cursesdisplay.h"
#include "common.h"

#define DEFAULT_FILE_ARRAY_SIZE 1

const char *opt_input_path;

struct lttngtop *copy;
pthread_t display_thread;
pthread_t timer_thread;

unsigned long refresh_display = 1 * NSEC_PER_SEC;
unsigned long last_display_update = 0;
int quit = 0;

enum {
	OPT_NONE = 0,
	OPT_HELP,
	OPT_LIST,
	OPT_VERBOSE,
	OPT_DEBUG,
	OPT_NAMES,
};

static struct poptOption long_options[] = {
	/* longName, shortName, argInfo, argPtr, value, descrip, argDesc */
	{ "help", 'h', POPT_ARG_NONE, NULL, OPT_HELP, NULL, NULL },
	{ NULL, 0, 0, NULL, 0, NULL, NULL },
};

void *refresh_thread(void *p)
{
	while (1) {
		if (quit)
			return NULL;
		sem_wait(&pause_sem);
		sem_post(&pause_sem);
		sem_post(&timer);
		sleep(refresh_display/NSEC_PER_SEC);
	}
}

void *ncurses_display(void *p)
{
	unsigned int current_display_index = 0;

	sem_wait(&bootstrap);
	init_ncurses();

	while (1) {
		sem_wait(&timer);
		sem_wait(&goodtodisplay);
		sem_wait(&pause_sem);

		copy = g_ptr_array_index(copies, current_display_index);
		assert(copy);
		display(current_display_index++);

		sem_post(&goodtoupdate);
		sem_post(&pause_sem);

		if (quit) {
			reset_ncurses();
			pthread_exit(0);
		}
	}
}

/*
 * hook on each event to check the timestamp and refresh the display if
 * necessary
 */
enum bt_cb_ret check_timestamp(struct bt_ctf_event *call_data, void *private_data)
{
	unsigned long timestamp;

	timestamp = bt_ctf_get_timestamp(call_data);
	if (timestamp == -1ULL)
		goto error;

	if (last_display_update == 0)
		last_display_update = timestamp;

	if (timestamp - last_display_update >= refresh_display) {
		sem_wait(&goodtoupdate);
		g_ptr_array_add(copies, get_copy_lttngtop(last_display_update,
					timestamp));
		sem_post(&goodtodisplay);
		sem_post(&bootstrap);
		last_display_update = timestamp;
	}
	return BT_CB_OK;

error:
	fprintf(stderr, "check_timestamp callback error\n");
	return BT_CB_ERROR_STOP;
}

/*
 * get_perf_counter : get or create and return a perf_counter struct for
 * either a process or a cpu (only one of the 2 parameters mandatory)
 */
struct perfcounter *get_perf_counter(const char *name, struct processtop *proc,
		struct cputime *cpu)
{
	struct perfcounter *ret, *global;
	GHashTable *table;

	if (proc)
		table = proc->perf;
	else if (cpu)
		table = cpu->perf;
	else
		goto error;

	ret = g_hash_table_lookup(table, (gpointer) name);
	if (ret)
		goto end;

	ret = g_new0(struct perfcounter, 1);
	/* by default, make it visible in the UI */
	ret->visible = 1;
	g_hash_table_insert(table, (gpointer) strdup(name), ret);

	global = g_hash_table_lookup(lttngtop.perf_list, (gpointer) name);
	if (!global) {
		global = g_new0(struct perfcounter, 1);
		memcpy(global, ret, sizeof(struct perfcounter));
		/* by default, sort on the first perf context */
		if (g_hash_table_size(lttngtop.perf_list) == 0)
			global->sort = 1;
		g_hash_table_insert(lttngtop.perf_list, (gpointer) strdup(name), global);
	}

end:
	return ret;

error:
	return NULL;
}

void update_perf_value(struct processtop *proc, struct cputime *cpu,
		const char *name, int value)
{
	struct perfcounter *cpu_perf, *process_perf;

	cpu_perf = get_perf_counter(name, NULL, cpu);
	if (cpu_perf->count < value) {
		process_perf = get_perf_counter(name, proc, NULL);
		process_perf->count += value - cpu_perf->count;
		cpu_perf->count = value;
	}
}

void extract_perf_counter_scope(struct bt_ctf_event *event,
		struct definition *scope,
		struct processtop *proc,
		struct cputime *cpu)
{
	struct definition const * const *list = NULL;
	unsigned int count;
	int i, ret;

	if (!scope)
		goto end;

	ret = bt_ctf_get_field_list(event, scope, &list, &count);
	if (ret < 0)
		goto end;

	for (i = 0; i < count; i++) {
		const char *name = bt_ctf_field_name(list[i]);
		if (strncmp(name, "_perf_", 6) == 0) {
			int value = bt_ctf_get_uint64(list[i]);
			if (bt_ctf_field_get_error())
				continue;
			update_perf_value(proc, cpu, name, value);
		}
	}

end:
	return;
}

void update_perf_counter(struct processtop *proc, struct bt_ctf_event *event)
{
	struct cputime *cpu;
	struct definition *scope;

	cpu = get_cpu(get_cpu_id(event));

	scope = bt_ctf_get_top_level_scope(event, BT_STREAM_EVENT_CONTEXT);
	extract_perf_counter_scope(event, scope, proc, cpu);

	scope = bt_ctf_get_top_level_scope(event, BT_STREAM_PACKET_CONTEXT);
	extract_perf_counter_scope(event, scope, proc, cpu);

	scope = bt_ctf_get_top_level_scope(event, BT_EVENT_CONTEXT);
	extract_perf_counter_scope(event, scope, proc, cpu);
}

enum bt_cb_ret fix_process_table(struct bt_ctf_event *call_data,
		void *private_data)
{
	int pid, tid, ppid;
	char *comm;
	struct processtop *parent, *child;
	unsigned long timestamp;

	/* FIXME : display nice error when missing context pid, tid, ppid and comm */

	timestamp = bt_ctf_get_timestamp(call_data);
	if (timestamp == -1ULL)
		goto error;

	pid = get_context_pid(call_data);
	if (pid == -1ULL) {
//		fprintf(stderr, "Missing pid context info\n");
		goto error;
	}
	tid = get_context_tid(call_data);
	if (tid == -1ULL) {
//		fprintf(stderr, "Missing tid context info\n");
		goto error;
	}
	ppid = get_context_ppid(call_data);
	if (ppid == -1ULL) {
//		fprintf(stderr, "Missing ppid context info\n");
		goto error;
	}
	comm = get_context_comm(call_data);
	if (!comm) {
//		fprintf(stderr, "Missing procname context info\n");
		goto error;
	}

	/* find or create the current process */
	child = find_process_tid(&lttngtop, tid, comm);
	if (!child)
		child = add_proc(&lttngtop, tid, comm, timestamp);
	update_proc(child, pid, tid, ppid, comm);

	if (pid != tid) {
		/* find or create the parent */
		parent = find_process_tid(&lttngtop, pid, comm);
		if (!parent) {
			parent = add_proc(&lttngtop, pid, comm, timestamp);
			parent->pid = pid;
		}

		/* attach the parent to the current process */
		child->threadparent = parent;
		add_thread(parent, child);
	}

	update_perf_counter(child, call_data);

	return BT_CB_OK;

error:
	return BT_CB_ERROR_STOP;
}

void init_lttngtop()
{
	copies = g_ptr_array_new();
	lttngtop.perf_list = g_hash_table_new(g_str_hash, g_str_equal);

	sem_init(&goodtodisplay, 0, 0);
	sem_init(&goodtoupdate, 0, 1);
	sem_init(&timer, 0, 1);
	sem_init(&bootstrap, 0, 0);
	sem_init(&pause_sem, 0, 1);
	sem_init(&end_trace_sem, 0, 0);

	lttngtop.process_table = g_ptr_array_new();
	lttngtop.files_table = g_ptr_array_new();
	lttngtop.cpu_table = g_ptr_array_new();
}

void usage(FILE *fp)
{
	fprintf(fp, "LTTngTop %s\n\n", VERSION);
	fprintf(fp, "Usage : lttngtop /path/to/trace\n");
}

/*
 * Return 0 if caller should continue, < 0 if caller should return
 * error, > 0 if caller should exit without reporting error.
 */
static int parse_options(int argc, char **argv)
{
	poptContext pc;
	int opt, ret = 0;

	if (argc == 1) {
		usage(stdout);
		return 1;   /* exit cleanly */
	}

	pc = poptGetContext(NULL, argc, (const char **) argv, long_options, 0);
	poptReadDefaultConfig(pc, 0);

	while ((opt = poptGetNextOpt(pc)) != -1) {
		switch (opt) {
			case OPT_HELP:
				usage(stdout);
				ret = 1;    /* exit cleanly */
				goto end;
			case OPT_LIST:
			//	list_formats(stdout);
				ret = 1;
				goto end;
			case OPT_VERBOSE:
//				babeltrace_verbose = 1;
				break;
			case OPT_DEBUG:
//				babeltrace_debug = 1;
				break;
			case OPT_NAMES:
//				opt_field_names = 1;
				break;
			default:
				ret = -EINVAL;
				goto end;
		}
	}

	opt_input_path = poptGetArg(pc);
	if (!opt_input_path) {
		ret = -EINVAL;
		goto end;
	}
end:
	if (pc) {
		poptFreeContext(pc);
	}
	return ret;
}

void iter_trace(struct bt_context *bt_ctx)
{
	struct bt_ctf_iter *iter;
	struct bt_iter_pos begin_pos;
	struct bt_ctf_event *event;
	int ret = 0;

	begin_pos.type = BT_SEEK_BEGIN;
	iter = bt_ctf_iter_create(bt_ctx, &begin_pos, NULL);

	/* at each event check if we need to refresh */
	bt_ctf_iter_add_callback(iter, 0, NULL, 0,
			check_timestamp,
			NULL, NULL, NULL);
	/* at each event, verify the status of the process table */
	bt_ctf_iter_add_callback(iter, 0, NULL, 0,
			fix_process_table,
			NULL, NULL, NULL);
	/* to handle the scheduling events */
	bt_ctf_iter_add_callback(iter,
			g_quark_from_static_string("sched_switch"),
			NULL, 0, handle_sched_switch, NULL, NULL, NULL);
	/* to clean up the process table */
	bt_ctf_iter_add_callback(iter,
			g_quark_from_static_string("sched_process_free"),
			NULL, 0, handle_sched_process_free, NULL, NULL, NULL);

	/* for IO top */
	bt_ctf_iter_add_callback(iter,
			g_quark_from_static_string("exit_syscall"),
			NULL, 0, handle_exit_syscall, NULL, NULL, NULL);
	bt_ctf_iter_add_callback(iter,
			g_quark_from_static_string("sys_write"),
			NULL, 0, handle_sys_write, NULL, NULL, NULL);
	bt_ctf_iter_add_callback(iter,
			g_quark_from_static_string("sys_read"),
			NULL, 0, handle_sys_read, NULL, NULL, NULL);
	bt_ctf_iter_add_callback(iter,
			g_quark_from_static_string("sys_open"),
			NULL, 0, handle_sys_open, NULL, NULL, NULL);

	bt_ctf_iter_add_callback(iter,
			g_quark_from_static_string("sys_close"),
			NULL, 0, handle_sys_close, NULL, NULL, NULL);
	while ((event = bt_ctf_iter_read_event(iter)) != NULL) {
		ret = bt_iter_next(bt_ctf_get_iter(iter));
		if (ret < 0)
			goto end_iter;
	}

	/* block until quit, we reached the end of the trace */
	sem_wait(&end_trace_sem);

end_iter:
	bt_iter_destroy(bt_ctf_get_iter(iter));
}

/*
 * bt_context_add_traces_recursive: Open a trace recursively
 * (copied from BSD code in converter/babeltrace.c)
 *
 * Find each trace present in the subdirectory starting from the given
 * path, and add them to the context. The packet_seek parameter can be
 * NULL: this specify to use the default format packet_seek.
 *
 * Return: 0 on success, nonzero on failure.
 * Unable to open toplevel: failure.
 * Unable to open some subdirectory or file: warn and continue;
 */
int bt_context_add_traces_recursive(struct bt_context *ctx, const char *path,
		const char *format_str,
		void (*packet_seek)(struct stream_pos *pos,
			size_t offset, int whence))
{
	FTS *tree;
	FTSENT *node;
	GArray *trace_ids;
	char lpath[PATH_MAX];
	char * const paths[2] = { lpath, NULL };
	int ret;

	/*
	 * Need to copy path, because fts_open can change it.
	 * It is the pointer array, not the strings, that are constant.
	 */
	strncpy(lpath, path, PATH_MAX);
	lpath[PATH_MAX - 1] = '\0';

	tree = fts_open(paths, FTS_NOCHDIR | FTS_LOGICAL, 0);
	if (tree == NULL) {
		fprintf(stderr, "[error] [Context] Cannot traverse \"%s\" for reading.\n",
				path);
		return -EINVAL;
	}

	trace_ids = g_array_new(FALSE, TRUE, sizeof(int));

	while ((node = fts_read(tree))) {
		int dirfd, metafd;

		if (!(node->fts_info & FTS_D))
			continue;

		dirfd = open(node->fts_accpath, 0);
		if (dirfd < 0) {
			fprintf(stderr, "[error] [Context] Unable to open trace "
				"directory file descriptor.\n");
			ret = dirfd;
			goto error;
		}
		metafd = openat(dirfd, "metadata", O_RDONLY);
		if (metafd < 0) {
			ret = close(dirfd);
			if (ret < 0) {
				perror("close");
				goto error;
			}
		} else {
			int trace_id;

			ret = close(metafd);
			if (ret < 0) {
				perror("close");
				goto error;
			}
			ret = close(dirfd);
			if (ret < 0) {
				perror("close");
				goto error;
			}

			trace_id = bt_context_add_trace(ctx,
				node->fts_accpath, format_str,
				packet_seek, NULL, NULL);
			if (trace_id < 0) {
				fprintf(stderr, "[error] [Context] opening trace \"%s\" from %s "
					"for reading.\n", node->fts_accpath, path);
				ret = trace_id;
				goto error;
			}
			g_array_append_val(trace_ids, trace_id);
		}
	}

	g_array_free(trace_ids, TRUE);
	return 0;

error:
	return ret;
}

int main(int argc, char **argv)
{
	int ret;
	struct bt_context *bt_ctx = NULL;

	ret = parse_options(argc, argv);
	if (ret < 0) {
		fprintf(stdout, "Error parsing options.\n\n");
		usage(stdout);
		exit(EXIT_FAILURE);
	} else if (ret > 0) {
		exit(EXIT_SUCCESS);
	}

	init_lttngtop();

	bt_ctx = bt_context_create();
	ret = bt_context_add_traces_recursive(bt_ctx, opt_input_path, "ctf", NULL);
	if (ret < 0) {
		printf("[error] Opening the trace\n");
		goto end;
	}

	pthread_create(&display_thread, NULL, ncurses_display, (void *) NULL);
	pthread_create(&timer_thread, NULL, refresh_thread, (void *) NULL);

	iter_trace(bt_ctx);

	quit = 1;
	pthread_join(display_thread, NULL);
	pthread_join(timer_thread, NULL);

end:
	bt_context_put(bt_ctx);
	return 0;
}

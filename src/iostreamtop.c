/*
 * Copyright (C) 2011 Mathieu Bain <mathieu.bain@polymtl.ca>
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <babeltrace/babeltrace.h>

#include "lttngtoptypes.h"
#include "common.h"
#include "iostreamtop.h"

void add_file(struct processtop *proc, struct files *file, int fd)
{
	if (proc->process_files_table->len <= fd) {
		g_ptr_array_set_size(proc->process_files_table, fd);
		g_ptr_array_add(proc->process_files_table, file);
	} else {
		g_ptr_array_index(proc->process_files_table, fd) = file;
	}
	file->fd = fd;
}


void insert_file(struct processtop *proc, int fd)
{
	struct files *tmp;

	if (fd >= proc->process_files_table->len) {
		tmp = g_new0(struct files, 1);
		tmp->name = "Unknown";
		add_file(proc, tmp, fd);
	} else {

		tmp = g_ptr_array_index(proc->process_files_table, fd);
		if (tmp == NULL) {
			tmp = g_new0(struct files, 1);
			tmp->name = "Unknown";
			tmp->read = 0;
			tmp->write = 0;
			tmp->fd = fd;
			add_file(proc, tmp, fd);
		}
	}
}

void close_file(struct processtop *proc, int fd)
{
	int len;

	len = proc->process_files_table->len;

	/*
	 * It is possible that a file was open before taking the trace
	 * and its fd could be greater than all of the others fd
	 * used by the process
	 */
	if (fd < len) {
		g_ptr_array_remove_index_fast(proc->process_files_table, fd);
		g_ptr_array_set_size(proc->process_files_table, len + 1);
	}
}

struct files *get_file(struct processtop *proc, int fd)
{
	struct files *tmp;
	tmp = g_ptr_array_index(proc->process_files_table, fd);
	return tmp;
}

void show_table(GPtrArray *tab)
{
	int i;
	struct files *file;

	for (i = 0 ; i < tab->len; i++) {
		file = g_ptr_array_index(tab, i);
		if (file == NULL)
			fprintf(stderr, "NULL, ");
		else
			fprintf(stderr, "%s, ", file->name);
	}
	fprintf(stderr, "]\n\n");
}

int update_iostream_ret(struct lttngtop *ctx, int tid, char *comm,
		unsigned long timestamp, int cpu_id, int ret)
{
	struct processtop *tmp;
	struct files *tmpfile;
	int err = 0;

	tmp = get_proc(ctx, tid, comm, timestamp);

	if (tmp->syscall_info != NULL) {
		if (tmp->syscall_info->type == __NR_read
			&& ret > 0) {
			tmp->totalfileread += ret;
			tmp->fileread += ret;
			tmpfile = get_file(tmp, tmp->syscall_info->fd);
			tmpfile->read += ret;
		} else if (tmp->syscall_info->type == __NR_write
			&& ret > 0) {
			tmp->totalfilewrite += ret;
			tmp->filewrite += ret;
			tmpfile = get_file(tmp, tmp->syscall_info->fd);
			tmpfile->write += ret;
		} else if (tmp->syscall_info->type == __NR_open
			&& ret > 0) {
			add_file(tmp, tmp->files_history->file, ret);
		} else {
			err = -1;
		}
		g_free(tmp->syscall_info);
		tmp->syscall_info = NULL;
 	}
	return err;
}

struct syscalls *create_syscall_info(unsigned int type, unsigned int cpu_id,
		unsigned int tid, int fd)
{
	struct syscalls *syscall_info;
	
	syscall_info = g_new0(struct syscalls, 1);
	syscall_info->type = type;
	syscall_info->cpu_id = cpu_id;
	syscall_info->tid = tid;
	syscall_info->fd = fd;

	return syscall_info;
}

struct file_history *create_file(struct file_history *history, char *file_name)
{
	struct files *new_file;
	struct file_history *new_history;

	new_file = g_new0(struct files, 1);
	new_history = g_new0(struct file_history, 1);
	new_file->name = strdup(file_name);
	new_file->read = 0;
	new_file->write = 0;
	new_history->file = new_file;
	new_history->next = history;

	return new_history;
}

enum bt_cb_ret handle_exit_syscall(struct bt_ctf_event *call_data,
		void *private_data)
{
	struct definition *scope;
	unsigned long timestamp;
	char *comm;
	uint64_t ret, tid;
	int64_t cpu_id;

	timestamp = bt_ctf_get_timestamp(call_data);
	if (timestamp == -1ULL)
		goto error;

	scope = bt_ctf_get_top_level_scope(call_data,
			BT_STREAM_EVENT_CONTEXT);
	comm = bt_ctf_get_char_array(bt_ctf_get_field(call_data,
				scope, "_procname"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing procname context info\n");
		goto error;
	}

	tid = bt_ctf_get_int64(bt_ctf_get_field(call_data,
				scope, "_tid"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing tid context info\n");
		goto error;
	}

	scope = bt_ctf_get_top_level_scope(call_data,
			BT_EVENT_FIELDS);
	ret = bt_ctf_get_int64(bt_ctf_get_field(call_data,
				scope, "_ret"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing ret context info\n");
		goto error;
	}

	scope = bt_ctf_get_top_level_scope(call_data,
			BT_STREAM_PACKET_CONTEXT);
	cpu_id = bt_ctf_get_uint64(bt_ctf_get_field(call_data,
				scope, "cpu_id"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing cpu_id context info\n");
		goto error;
	}

	/*
	 * if we encounter an exit_syscall and
	 * it is not for a syscall read or write
	 * we just abort the execution of this callback
	 */
	if ((update_iostream_ret(&lttngtop, tid, comm, timestamp, cpu_id, ret)) < 0)
		return BT_CB_ERROR_CONTINUE;

	return BT_CB_OK;

error:
	return BT_CB_ERROR_STOP;
}


enum bt_cb_ret handle_sys_write(struct bt_ctf_event *call_data,
		void *private_data)
{
	struct definition *scope;
	struct processtop *tmp;
	unsigned long timestamp;
	uint64_t cpu_id;
	char *comm;
	int64_t tid;
	int fd;

	timestamp = bt_ctf_get_timestamp(call_data);
	if (timestamp == -1ULL)
		goto error;

	scope = bt_ctf_get_top_level_scope(call_data,
			BT_STREAM_EVENT_CONTEXT);
	comm = bt_ctf_get_char_array(bt_ctf_get_field(call_data,
				scope, "_procname"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing procname context info\n");
		goto error;
	}

	tid = bt_ctf_get_int64(bt_ctf_get_field(call_data,
				scope, "_tid"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing tid context info\n");
		goto error;
	}

	scope = bt_ctf_get_top_level_scope(call_data,
			BT_STREAM_PACKET_CONTEXT);
	cpu_id = bt_ctf_get_uint64(bt_ctf_get_field(call_data,
				scope, "cpu_id"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing cpu_id context info\n");
		goto error;
	}

	scope = bt_ctf_get_top_level_scope(call_data,
			BT_EVENT_FIELDS);
	fd = bt_ctf_get_uint64(bt_ctf_get_field(call_data,
				scope, "_fd"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing fd context info\n");
		goto error;
	}

	tmp = get_proc(&lttngtop, tid, comm, timestamp);
	tmp->syscall_info = create_syscall_info(__NR_write, cpu_id, tid, fd);

	insert_file(tmp, fd);

	return BT_CB_OK;

error:
	return BT_CB_ERROR_STOP;
}

enum bt_cb_ret handle_sys_read(struct bt_ctf_event *call_data,
		void *private_data)
{
	struct processtop *tmp;
	struct definition *scope;
	unsigned long timestamp;
	uint64_t cpu_id;
	char *comm;
	int64_t tid;
	int fd;

	timestamp = bt_ctf_get_timestamp(call_data);
	if (timestamp == -1ULL)
		goto error;

	scope = bt_ctf_get_top_level_scope(call_data,
			BT_STREAM_EVENT_CONTEXT);
	comm = bt_ctf_get_char_array(bt_ctf_get_field(call_data,
				scope, "_procname"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing procname context info\n");
		goto error;
	}

	tid = bt_ctf_get_int64(bt_ctf_get_field(call_data,
				scope, "_tid"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing tid context info\n");
		goto error;
	}

	scope = bt_ctf_get_top_level_scope(call_data,
			BT_STREAM_PACKET_CONTEXT);
	cpu_id = bt_ctf_get_uint64(bt_ctf_get_field(call_data,
				scope, "cpu_id"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing cpu_id context info\n");
		goto error;
	}

	scope = bt_ctf_get_top_level_scope(call_data,
			BT_EVENT_FIELDS);
	fd = bt_ctf_get_uint64(bt_ctf_get_field(call_data,
				scope, "_fd"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing fd context info\n");
		goto error;
	}

	tmp = get_proc(&lttngtop, tid, comm, timestamp);
	tmp->syscall_info = create_syscall_info(__NR_read, cpu_id, tid, fd);

	insert_file(tmp, fd);

	return BT_CB_OK;

error:
	return BT_CB_ERROR_STOP;
}


enum bt_cb_ret handle_sys_open(struct bt_ctf_event *call_data,
		void *private_data)
{

	struct processtop *tmp;
	struct definition *scope;
	unsigned long timestamp;
	uint64_t cpu_id;
	char *comm;
	int64_t tid;
	char *file;

	timestamp = bt_ctf_get_timestamp(call_data);
	if (timestamp == -1ULL)
		goto error;

	scope = bt_ctf_get_top_level_scope(call_data,
			BT_STREAM_EVENT_CONTEXT);
	comm = bt_ctf_get_char_array(bt_ctf_get_field(call_data,
				scope, "_procname"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing procname context info\n");
		goto error;
	}

	tid = bt_ctf_get_int64(bt_ctf_get_field(call_data,
				scope, "_tid"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing tid context info\n");
		goto error;
	}

	scope = bt_ctf_get_top_level_scope(call_data,
			BT_STREAM_PACKET_CONTEXT);
	cpu_id = bt_ctf_get_uint64(bt_ctf_get_field(call_data,
				scope, "cpu_id"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing cpu_id context info\n");
		goto error;
	}

	scope = bt_ctf_get_top_level_scope(call_data,
			BT_EVENT_FIELDS);
	file = bt_ctf_get_string(bt_ctf_get_field(call_data,
				scope, "_filename"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing fd context info\n");
		goto error;
	}

	tmp = get_proc(&lttngtop, tid, comm, timestamp);
	tmp->syscall_info = create_syscall_info(__NR_open, cpu_id, tid, -1);

	tmp->files_history = create_file(tmp->files_history, file);

	return BT_CB_OK;

error:
	return BT_CB_ERROR_STOP;
}


enum bt_cb_ret handle_sys_close(struct bt_ctf_event *call_data,
		void *private_data)
{
	struct definition *scope;
	unsigned long timestamp;
	int64_t tid;
	struct processtop *tmp;
	char *comm;
	int fd;

	timestamp = bt_ctf_get_timestamp(call_data);
	if (timestamp == -1ULL)
		goto error;

	scope = bt_ctf_get_top_level_scope(call_data,
			BT_STREAM_EVENT_CONTEXT);
	comm = bt_ctf_get_char_array(bt_ctf_get_field(call_data,
				scope, "_procname"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing procname context info\n");
		goto error;
	}

	tid = bt_ctf_get_int64(bt_ctf_get_field(call_data,
				scope, "_tid"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing tid context info\n");
		goto error;
	}

	scope = bt_ctf_get_top_level_scope(call_data,
			BT_EVENT_FIELDS);
	fd = bt_ctf_get_uint64(bt_ctf_get_field(call_data,
				scope, "_fd"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing fd context info\n");
		goto error;
	}

	tmp = get_proc(&lttngtop, tid, comm, timestamp);
	close_file(tmp, fd);

	return BT_CB_OK;

error:
	return BT_CB_ERROR_STOP;
}

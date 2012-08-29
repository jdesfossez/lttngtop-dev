/*
 * Copyright (C) 2011-2012 Mathieu Bain <mathieu.bain@polymtl.ca>
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
	struct files *tmp_file;
	struct processtop *parent;
	int size;
	int i;

	size = proc->process_files_table->len;
	parent = proc->threadparent;
	if (parent)
		insert_file(parent, fd);
	if (size <= fd) {
		/* Add NULL file structures for undefined FDs */
		for (i = size; i < fd; i++) {
			g_ptr_array_add(proc->process_files_table, NULL);
		}
		g_ptr_array_add(proc->process_files_table, file);
	} else {
		tmp_file = g_ptr_array_index(proc->process_files_table, fd);
		if (tmp_file == NULL)
			g_ptr_array_index(proc->process_files_table, fd) = file;
		else {
			if (strcmp(tmp_file->name, file->name) != 0) {
				size = proc->process_files_table->len;
				g_ptr_array_set_size(proc->process_files_table,
								size+1);
				g_ptr_array_index(proc->process_files_table,
							size) = tmp_file;
				g_ptr_array_index(proc->process_files_table,
							fd) = file;
			} else
				tmp_file->flag = __NR_open;
		}
	}
	/*
	 * The file may have be created in the parent
	 */
	if (file->flag == -1) {
		file->fd = fd;
		file->flag = __NR_open;
		lttngtop.nbfiles++;
		lttngtop.nbnewfiles++;
	}
}

/*
 * Edit the file
 * Called by handled_statedump_filename
 */
void edit_file(struct processtop *proc, struct files *file, int fd)
{
	int size = proc->process_files_table->len;
	struct files *tmpfile;

	if (fd >= size) {
		add_file(proc, file, fd);
	} else {
		tmpfile = g_ptr_array_index(proc->process_files_table, fd);
		if (tmpfile) {
			tmpfile->name = strdup(file->name);
			free(file);
		} else
			add_file(proc, file, fd);
	}
}

void insert_file(struct processtop *proc, int fd)
{
	struct files *tmp;
	struct files *tmp_parent;
	struct processtop *parent;

	if (fd < 0)
		return;
	if (fd >= proc->process_files_table->len) {
		tmp = g_new0(struct files, 1);
		tmp->name = "Unknown";
		tmp->read = 0;
		tmp->write = 0;
		tmp->fd = fd;
		tmp->flag = -1;
		add_file(proc, tmp, fd);
	} else {
		tmp = g_ptr_array_index(proc->process_files_table, fd);
		if (tmp == NULL) {
			tmp = g_new0(struct files, 1);
			tmp->name = "Unknown";
			tmp->read = 0;
			tmp->write = 0;
			tmp->fd = fd;
			tmp->flag = -1;
			add_file(proc, tmp, fd);
		} else {
			parent = proc->threadparent;
			if (parent) {
				tmp_parent = g_ptr_array_index(
					parent->process_files_table, fd);
				if (tmp_parent &&
				   (strcmp(tmp->name, tmp_parent->name)) != 0)
					tmp->name = strdup(tmp_parent->name);
			}
		}
	}
}

void close_file(struct processtop *proc, int fd)
{
	struct files *file;

	file = get_file(proc, fd);
	if (file != NULL) {
		file->flag = __NR_close;
		lttngtop.nbfiles--;
	}
	lttngtop.nbclosedfiles++;
}

struct files *get_file(struct processtop *proc, int fd)
{
	int len;
	struct files *tmp = NULL;

	len = proc->process_files_table->len;

	/*
	 * It is possible that a file was open before taking the trace
	 * and its fd could be greater than all of the others fd
	 * used by the process
	 */
	if (fd < len && fd >= 0)
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

void show_history(struct file_history *history)
{
	struct file_history *tmp = history;

	while (tmp != NULL) {
		fprintf(stderr, "fd = %d, name = %s\n", tmp->file->fd,
					tmp->file->name);
		tmp = tmp->next;
	}

}

int update_iostream_ret(struct lttngtop *ctx, int tid, char *comm,
		unsigned long timestamp, uint64_t cpu_id, int ret,
		char *hostname)
{
	struct processtop *tmp;
	struct files *tmpfile;
	int err = 0;

	tmp = get_proc(ctx, tid, comm, timestamp, hostname);

	if (!tmp) {
		err = -1;
		goto end;
	}
	if (tmp->syscall_info != NULL) {
		if (tmp->syscall_info->type == __NR_read
			&& ret > 0) {
			tmp->totalfileread += ret;
			tmp->fileread += ret;
			tmpfile = get_file(tmp, tmp->syscall_info->fd);
			if (tmpfile)
				tmpfile->read += ret;
		} else if (tmp->syscall_info->type == __NR_write
			&& ret > 0) {
			tmp->totalfilewrite += ret;
			tmp->filewrite += ret;
			tmpfile = get_file(tmp, tmp->syscall_info->fd);
			if (tmpfile)
				tmpfile->write += ret;
		} else if (tmp->syscall_info->type == __NR_open
			&& ret > 0) {
			tmpfile = tmp->files_history->file;
			add_file(tmp, tmpfile, ret);
			tmpfile->fd = ret;
		} else {
			err = -1;
		}
		g_free(tmp->syscall_info);
		tmp->syscall_info = NULL;
 	}

end:
	return err;
}

struct syscalls *create_syscall_info(unsigned int type, uint64_t cpu_id,
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
	new_file->flag = -1;
	new_history->file = new_file;
	new_history->next = history;

	return new_history;
}

enum bt_cb_ret handle_exit_syscall(struct bt_ctf_event *call_data,
		void *private_data)
{
	const struct bt_definition *scope;
	unsigned long timestamp;
	char *comm;
	uint64_t ret, tid;
	uint64_t cpu_id;
	char *hostname;

	timestamp = bt_ctf_get_timestamp(call_data);
	if (timestamp == -1ULL)
		goto error;

	comm = get_context_comm(call_data);
	tid = get_context_tid(call_data);

	scope = bt_ctf_get_top_level_scope(call_data,
			BT_EVENT_FIELDS);
	ret = bt_ctf_get_int64(bt_ctf_get_field(call_data,
				scope, "_ret"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing ret context info\n");
		goto error;
	}

	cpu_id = get_cpu_id(call_data);
	hostname = get_context_hostname(call_data);

	/*
	 * if we encounter an exit_syscall and
	 * it is not for a syscall read or write
	 * we just abort the execution of this callback
	 */
	if ((update_iostream_ret(&lttngtop, tid, comm, timestamp, cpu_id,
					ret, hostname)) < 0)
		return BT_CB_ERROR_CONTINUE;

	return BT_CB_OK;

error:
	return BT_CB_ERROR_STOP;
}


enum bt_cb_ret handle_sys_write(struct bt_ctf_event *call_data,
		void *private_data)
{
	const struct bt_definition *scope;
	struct processtop *tmp;
	unsigned long timestamp;
	uint64_t cpu_id;
	int64_t tid;
	char *procname, *hostname;
	int fd;

	timestamp = bt_ctf_get_timestamp(call_data);
	if (timestamp == -1ULL)
		goto error;

	tid = get_context_tid(call_data);
	cpu_id = get_cpu_id(call_data);

	procname = get_context_comm(call_data);
	hostname = get_context_hostname(call_data);

	scope = bt_ctf_get_top_level_scope(call_data,
			BT_EVENT_FIELDS);
	fd = bt_ctf_get_uint64(bt_ctf_get_field(call_data,
				scope, "_fd"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing fd context info\n");
		goto error;
	}

	tmp = get_proc(&lttngtop, tid, procname, timestamp, hostname);
	if (!tmp)
		goto end;

	tmp->syscall_info = create_syscall_info(__NR_write, cpu_id, tid, fd);

	insert_file(tmp, fd);

end:
	return BT_CB_OK;

error:
	return BT_CB_ERROR_STOP;
}

enum bt_cb_ret handle_sys_read(struct bt_ctf_event *call_data,
		void *private_data)
{
	struct processtop *tmp;
	const struct bt_definition *scope;
	unsigned long timestamp;
	uint64_t cpu_id;
	int64_t tid;
	char *procname;
	int fd;
	char *hostname;

	timestamp = bt_ctf_get_timestamp(call_data);
	if (timestamp == -1ULL)
		goto error;

	tid = get_context_tid(call_data);
	cpu_id = get_cpu_id(call_data);

	procname = get_context_comm(call_data);
	hostname = get_context_hostname(call_data);

	scope = bt_ctf_get_top_level_scope(call_data,
			BT_EVENT_FIELDS);
	fd = bt_ctf_get_uint64(bt_ctf_get_field(call_data,
				scope, "_fd"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing fd context info\n");
		goto error;
	}

	tmp = get_proc(&lttngtop, tid, procname, timestamp, hostname);
	if (!tmp)
		goto end;

	tmp->syscall_info = create_syscall_info(__NR_read, cpu_id, tid, fd);

	insert_file(tmp, fd);

end:
	return BT_CB_OK;

error:
	return BT_CB_ERROR_STOP;
}


enum bt_cb_ret handle_sys_open(struct bt_ctf_event *call_data,
		void *private_data)
{

	struct processtop *tmp;
	const struct bt_definition *scope;
	unsigned long timestamp;
	uint64_t cpu_id;
	int64_t tid;
	char *procname, *hostname;
	char *file;

	timestamp = bt_ctf_get_timestamp(call_data);
	if (timestamp == -1ULL)
		goto error;

	tid = get_context_tid(call_data);
	cpu_id = get_cpu_id(call_data);

	procname = get_context_comm(call_data);
	hostname = get_context_hostname(call_data);

	scope = bt_ctf_get_top_level_scope(call_data,
			BT_EVENT_FIELDS);
	file = bt_ctf_get_string(bt_ctf_get_field(call_data,
				scope, "_filename"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing file name context info\n");
		goto error;
	}

	tmp = get_proc(&lttngtop, tid, procname, timestamp, hostname);
	if (!tmp)
		goto end;

	tmp->syscall_info = create_syscall_info(__NR_open, cpu_id, tid, -1);

	tmp->files_history = create_file(tmp->files_history, file);

end:
	return BT_CB_OK;

error:
	return BT_CB_ERROR_STOP;
}


enum bt_cb_ret handle_sys_close(struct bt_ctf_event *call_data,
		void *private_data)
{
	const struct bt_definition *scope;
	struct processtop *tmp;
	unsigned long timestamp;
	int64_t tid;
	char *procname;
	int fd;
	char *hostname;

	timestamp = bt_ctf_get_timestamp(call_data);
	if (timestamp == -1ULL)
		goto error;

	tid = get_context_tid(call_data);

	procname = get_context_comm(call_data);
	hostname = get_context_hostname(call_data);

	scope = bt_ctf_get_top_level_scope(call_data,
			BT_EVENT_FIELDS);
	fd = bt_ctf_get_uint64(bt_ctf_get_field(call_data,
				scope, "_fd"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing fd context info\n");
		goto error;
	}

	tmp = get_proc(&lttngtop, tid, procname, timestamp, hostname);
	if (!tmp)
		goto end;

	close_file(tmp, fd);

end:
	return BT_CB_OK;

error:
	return BT_CB_ERROR_STOP;
}

enum bt_cb_ret handle_statedump_file_descriptor(struct bt_ctf_event *call_data,
		void *private_data)
{
	const struct bt_definition *scope;
	struct processtop *parent;
	struct files *file;
	unsigned long timestamp;
	int64_t pid;
	char *file_name, *hostname;
	int fd;

	timestamp = bt_ctf_get_timestamp(call_data);
	if (timestamp == -1ULL)
		goto error;

	scope = bt_ctf_get_top_level_scope(call_data,
			 BT_EVENT_FIELDS);
	pid = bt_ctf_get_int64(bt_ctf_get_field(call_data,
			     scope, "_pid"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing tid context info\n");
		goto error;
	}

	scope = bt_ctf_get_top_level_scope(call_data,
			BT_EVENT_FIELDS);
	fd = bt_ctf_get_int64(bt_ctf_get_field(call_data,
				scope, "_fd"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing fd context info\n");
		goto error;
	}

	scope = bt_ctf_get_top_level_scope(call_data,
			BT_EVENT_FIELDS);
	file_name = bt_ctf_get_string(bt_ctf_get_field(call_data,
				scope, "_filename"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing file name context info\n");
		goto error;
	}
	hostname = get_context_hostname(call_data);

	parent = get_proc_pid(&lttngtop, pid, pid, timestamp, hostname);
	if (!parent)
		goto end;

	parent->files_history = create_file(parent->files_history, file_name);
	file = parent->files_history->file;
	edit_file(parent, file, fd);

end:
	return BT_CB_OK;

error:
	return BT_CB_ERROR_STOP;
}

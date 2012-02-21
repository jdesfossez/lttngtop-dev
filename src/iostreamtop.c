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

#include <babeltrace/babeltrace.h>

#include "lttngtoptypes.h"
#include "common.h"
#include "iostreamtop.h"

#include <stdlib.h>

int update_iostream_ret(struct lttngtop *ctx, int tid, char *comm,
		unsigned long timestamp, int cpu_id, int ret)
{
	struct processtop *tmp;
	int err = 0;

	tmp = get_proc(ctx, tid, comm, timestamp);
	if ((tmp->iostream->syscall_info != NULL) && (tmp->iostream->syscall_info->cpu_id == cpu_id)) {
		if (tmp->iostream->syscall_info->type == __NR_read && ret > 0) {
			tmp->iostream->ret_read += ret;
			tmp->iostream->ret_total += ret;
		} else if(tmp->iostream->syscall_info->type == __NR_write && ret > 0) {
			tmp->iostream->ret_write += ret;
			tmp->iostream->ret_total += ret;
		} else{
			err = -1;
		}
		free(tmp->iostream->syscall_info);
		tmp->iostream->syscall_info = NULL;
	}

	return err;
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
	 * if we encounter an exit_syscall and it is not for a syscall read or write
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
	struct syscalls *syscall_info;
	unsigned long timestamp;
	uint64_t cpu_id;
	char *comm;
	int64_t tid;

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

	syscall_info = malloc(sizeof(struct syscalls));
	syscall_info->cpu_id = cpu_id;
	syscall_info->type = __NR_write;
	syscall_info->tid =  tid;
	tmp = get_proc(&lttngtop, tid, comm, timestamp);
	tmp->iostream->syscall_info = syscall_info;

	return BT_CB_OK;

error:
	return BT_CB_ERROR_STOP;
}

enum bt_cb_ret handle_sys_read(struct bt_ctf_event *call_data,
		void *private_data)
{
	struct processtop *tmp;
	struct definition *scope;
	struct syscalls * syscall_info;
	unsigned long timestamp;
	uint64_t cpu_id;
	char *comm;
	int64_t tid;

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

	syscall_info = malloc(sizeof(struct syscalls));
	syscall_info->cpu_id = cpu_id;
	syscall_info->type = __NR_read;
	syscall_info->tid =  tid;
	tmp = get_proc(&lttngtop, tid, comm, timestamp);
	tmp->iostream->syscall_info = syscall_info;

	return BT_CB_OK;

error:
	return BT_CB_ERROR_STOP;
}


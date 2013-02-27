/*
 * Copyright (C) 2011-2012 Julien Desfossez
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

#include <babeltrace/babeltrace.h>

#include "lttngtoptypes.h"
#include "common.h"
#include "cputop.h"

void update_cputop_data(unsigned long timestamp, int64_t cpu, int prev_pid,
		int next_pid, char *prev_comm, char *next_comm, char *hostname)
{
	struct cputime *tmpcpu;
	unsigned long elapsed;

	tmpcpu = get_cpu(cpu);

	if (tmpcpu->current_task && tmpcpu->current_task->pid == prev_pid) {
		elapsed = timestamp - tmpcpu->task_start;
		tmpcpu->current_task->totalcpunsec += elapsed;
		tmpcpu->current_task->threadstotalcpunsec += elapsed;
		if (tmpcpu->current_task->threadparent &&
				tmpcpu->current_task->pid != tmpcpu->current_task->tid)
			tmpcpu->current_task->threadparent->threadstotalcpunsec += elapsed;
	}

	if (next_pid != 0)
		tmpcpu->current_task = get_proc(&lttngtop, next_pid, next_comm,
				timestamp, hostname);
	else
		tmpcpu->current_task = NULL;

	tmpcpu->task_start = timestamp;
}

enum bt_cb_ret handle_sched_switch(struct bt_ctf_event *call_data,
		void *private_data)
{
	const struct bt_definition *scope;
	unsigned long timestamp;
	uint64_t cpu_id;
	char *prev_comm, *next_comm;
	int prev_tid, next_tid;
	char *hostname = NULL;

	timestamp = bt_ctf_get_timestamp(call_data);
	if (timestamp == -1ULL)
		goto error;

	scope = bt_ctf_get_top_level_scope(call_data,
			BT_EVENT_FIELDS);
	prev_comm = bt_ctf_get_char_array(bt_ctf_get_field(call_data,
				scope, "_prev_comm"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing prev_comm context info\n");
		goto error;
	}

	next_comm = bt_ctf_get_char_array(bt_ctf_get_field(call_data,
				scope, "_next_comm"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing next_comm context info\n");
		goto error;
	}

	prev_tid = bt_ctf_get_int64(bt_ctf_get_field(call_data,
				scope, "_prev_tid"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing prev_tid context info\n");
		goto error;
	}

	next_tid = bt_ctf_get_int64(bt_ctf_get_field(call_data,
				scope, "_next_tid"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing next_tid context info\n");
		goto error;
	}

	cpu_id = get_cpu_id(call_data);

	update_cputop_data(timestamp, cpu_id, prev_tid, next_tid,
			prev_comm, next_comm, hostname);

	return BT_CB_OK;

error:
	return BT_CB_ERROR_STOP;
}

enum bt_cb_ret handle_sched_process_free(struct bt_ctf_event *call_data,
		void *private_data)
{
	const struct bt_definition *scope;
	unsigned long timestamp;
	char *comm;
	int tid;

	timestamp = bt_ctf_get_timestamp(call_data);
	if (timestamp == -1ULL)
		goto error;

	scope = bt_ctf_get_top_level_scope(call_data,
			BT_EVENT_FIELDS);
	comm = bt_ctf_get_char_array(bt_ctf_get_field(call_data,
				scope, "_comm"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing procname context info\n");
		goto error;
	}

	tid = bt_ctf_get_int64(bt_ctf_get_field(call_data,
				scope, "_tid"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing tid field\n");
		goto error;
	}

	death_proc(&lttngtop, tid, comm, timestamp);

	return BT_CB_OK;

error:
	return BT_CB_ERROR_STOP;

}


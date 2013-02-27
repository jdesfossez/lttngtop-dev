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

#include <babeltrace/ctf/events.h>
#include <stdlib.h>
#include <linux/unistd.h>
#include <string.h>
#include "common.h"

uint64_t get_cpu_id(const struct bt_ctf_event *event)
{
	const struct bt_definition *scope;
	uint64_t cpu_id;

	scope = bt_ctf_get_top_level_scope(event, BT_STREAM_PACKET_CONTEXT);
	cpu_id = bt_ctf_get_uint64(bt_ctf_get_field(event, scope, "cpu_id"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "[error] get cpu_id\n");
		return -1ULL;
	}

	return cpu_id;
}

uint64_t get_context_tid(const struct bt_ctf_event *event)
{
	const struct bt_definition *scope;
	uint64_t tid;

	scope = bt_ctf_get_top_level_scope(event, BT_STREAM_EVENT_CONTEXT);
	tid = bt_ctf_get_int64(bt_ctf_get_field(event,
				scope, "_tid"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing tid context info\n");
		return -1ULL;
	}

	return tid;
}

uint64_t get_context_pid(const struct bt_ctf_event *event)
{
	const struct bt_definition *scope;
	uint64_t pid;

	scope = bt_ctf_get_top_level_scope(event, BT_STREAM_EVENT_CONTEXT);
	pid = bt_ctf_get_int64(bt_ctf_get_field(event,
				scope, "_pid"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing pid context info\n");
		return -1ULL;
	}

	return pid;
}

uint64_t get_context_ppid(const struct bt_ctf_event *event)
{
	const struct bt_definition *scope;
	uint64_t ppid;

	scope = bt_ctf_get_top_level_scope(event, BT_STREAM_EVENT_CONTEXT);
	ppid = bt_ctf_get_int64(bt_ctf_get_field(event,
				scope, "_ppid"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing ppid context info\n");
		return -1ULL;
	}

	return ppid;
}

uint64_t get_context_vtid(const struct bt_ctf_event *event)
{
	const struct definition *scope;
	uint64_t vtid;

	scope = bt_ctf_get_top_level_scope(event, BT_STREAM_EVENT_CONTEXT);
	vtid = bt_ctf_get_int64(bt_ctf_get_field(event,
				scope, "_vtid"));
	if (bt_ctf_field_get_error()) {
		return -1ULL;
	}

	return vtid;
}

uint64_t get_context_vpid(const struct bt_ctf_event *event)
{
	const struct definition *scope;
	uint64_t vpid;

	scope = bt_ctf_get_top_level_scope(event, BT_STREAM_EVENT_CONTEXT);
	vpid = bt_ctf_get_int64(bt_ctf_get_field(event,
				scope, "_vpid"));
	if (bt_ctf_field_get_error()) {
		return -1ULL;
	}

	return vpid;
}

uint64_t get_context_vppid(const struct bt_ctf_event *event)
{
	const struct definition *scope;
	uint64_t vppid;

	scope = bt_ctf_get_top_level_scope(event, BT_STREAM_EVENT_CONTEXT);
	vppid = bt_ctf_get_int64(bt_ctf_get_field(event,
				scope, "_vppid"));
	if (bt_ctf_field_get_error()) {
		return -1ULL;
	}

	return vppid;
}

char *get_context_comm(const struct bt_ctf_event *event)
{
	const struct bt_definition *scope;
	char *comm;

	scope = bt_ctf_get_top_level_scope(event, BT_STREAM_EVENT_CONTEXT);
	comm = bt_ctf_get_char_array(bt_ctf_get_field(event,
				scope, "_procname"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing comm context info\n");
		return NULL;
	}

	return comm;
}

char *get_context_hostname(const struct bt_ctf_event *event)
{
	const struct definition *scope;
	char *hostname;

	scope = bt_ctf_get_top_level_scope(event, BT_STREAM_EVENT_CONTEXT);
	hostname = bt_ctf_get_char_array(bt_ctf_get_field(event,
				scope, "_hostname"));
	if (bt_ctf_field_get_error()) {
		return NULL;
	}

	return hostname;
}

/*
 * To get the parent process, put the pid in the tid field
 * because the parent process gets pid = tid
 */
struct processtop *find_process_tid(struct lttngtop *ctx, int tid, char *comm)
{
	struct processtop *tmp;

	tmp = g_hash_table_lookup(ctx->process_hash_table,
			(gconstpointer) (unsigned long) tid);

	return tmp;
}

struct processtop* add_proc(struct lttngtop *ctx, int tid, char *comm,
		unsigned long timestamp, char *hostname)
{
	struct processtop *newproc;
	struct host *host;

	/* if the PID already exists, we just rename the process */
	/* FIXME : need to integrate with clone/fork/exit to be accurate */
	newproc = find_process_tid(ctx, tid, comm);

	if (!newproc) {
		newproc = g_new0(struct processtop, 1);
		newproc->tid = tid;
		newproc->birth = timestamp;
		newproc->process_files_table = g_ptr_array_new();
		newproc->files_history = NULL;
		newproc->totalfileread = 0;
		newproc->totalfilewrite = 0;
		newproc->fileread = 0;
		newproc->filewrite = 0;
		newproc->syscall_info = NULL;
		newproc->threadparent = NULL;
		newproc->threads = g_ptr_array_new();
		newproc->perf = g_hash_table_new(g_str_hash, g_str_equal);
		g_ptr_array_add(ctx->process_table, newproc);
		g_hash_table_insert(ctx->process_hash_table,
				(gpointer) (unsigned long) tid, newproc);
		if (lookup_tid_list(tid)) {
			add_filter_tid_list(newproc);
		}
		ctx->nbnewthreads++;
		ctx->nbthreads++;
	}
	newproc->comm = strdup(comm);
	if (hostname) {
		host = lookup_hostname_list(hostname);
		if (!host)
			host = add_hostname_list(hostname, 0);
		if (!newproc->host || (newproc->host != host))
			newproc->host = host;
		if (is_hostname_filtered(hostname)) {
			add_filter_tid_list(newproc);
		}
	}

	return newproc;
}

struct processtop* update_proc(struct processtop* proc, int pid, int tid,
		int ppid, int vpid, int vtid, int vppid, char *comm, char *hostname)
{
	struct host *host;

	if (proc) {
		proc->pid = pid;
		proc->tid = tid;
		proc->ppid = ppid;
		proc->vpid = vpid;
		proc->vtid = vtid;
		proc->vppid = vppid;
		if (strcmp(proc->comm, comm) != 0) {
			free(proc->comm);
			proc->comm = strdup(comm);
		}
		if (hostname && !proc->host) {
			host = lookup_hostname_list(hostname);
			if (!host)
				host = add_hostname_list(hostname, 0);
			if (!proc->host || (proc->host != host))
				proc->host = host;
			if (is_hostname_filtered(hostname)) {
				add_filter_tid_list(proc);
			}
		}
	}
	return proc;
}

/*
 * This function just sets the time of death of a process.
 * When we rotate the cputime we remove it from the process list.
 */
void death_proc(struct lttngtop *ctx, int tid, char *comm,
		unsigned long timestamp)
{
	struct processtop *tmp;
	tmp = find_process_tid(ctx, tid, comm);

	g_hash_table_remove(ctx->process_hash_table,
			(gpointer) (unsigned long) tid);
	if (tmp && strcmp(tmp->comm, comm) == 0) {
		tmp->death = timestamp;
		ctx->nbdeadthreads++;
		ctx->nbthreads--;
	}
}

struct processtop* get_proc(struct lttngtop *ctx, int tid, char *comm,
		unsigned long timestamp, char *hostname)
{
	struct processtop *tmp;

	tmp = find_process_tid(ctx, tid, comm);
	if (tmp && strcmp(tmp->comm, comm) == 0) {
		return tmp;
	}
	return add_proc(ctx, tid, comm, timestamp, hostname);
}

struct processtop *get_proc_pid(struct lttngtop *ctx, int tid, int pid,
		unsigned long timestamp, char *hostname)
{
	struct processtop *tmp;
	tmp = find_process_tid(ctx, tid, NULL);
	if (tmp && tmp->pid == pid)
		return tmp;
	return add_proc(ctx, tid, "Unknown", timestamp, hostname);
}

void add_thread(struct processtop *parent, struct processtop *thread)
{
	gint i;
	struct processtop *tmp;

	if (!parent)
		return;

	for (i = 0; i < parent->threads->len; i++) {
		tmp = g_ptr_array_index(parent->threads, i);
		if (tmp == thread)
			return;
	}
	g_ptr_array_add(parent->threads, thread);
}

struct cputime* add_cpu(int cpu)
{
	struct cputime *newcpu;

	newcpu = g_new0(struct cputime, 1);
	newcpu->id = cpu;
	newcpu->current_task = NULL;
	newcpu->perf = g_hash_table_new(g_str_hash, g_str_equal);

	g_ptr_array_add(lttngtop.cpu_table, newcpu);

	return newcpu;
}
struct cputime* get_cpu(int cpu)
{
	gint i;
	struct cputime *tmp;

	for (i = 0; i < lttngtop.cpu_table->len; i++) {
		tmp = g_ptr_array_index(lttngtop.cpu_table, i);
		if (tmp->id == cpu)
			return tmp;
	}

	return add_cpu(cpu);
}

/*
 * At the end of a sampling period, we need to display the cpu time for each
 * process and to reset it to zero for the next period
 */
void rotate_cputime(unsigned long end)
{
	gint i;
	struct cputime *tmp;
	unsigned long elapsed;

	for (i = 0; i < lttngtop.cpu_table->len; i++) {
		tmp = g_ptr_array_index(lttngtop.cpu_table, i);
		elapsed = end - tmp->task_start;
		if (tmp->current_task) {
			tmp->current_task->totalcpunsec += elapsed;
			tmp->current_task->threadstotalcpunsec += elapsed;
			if (tmp->current_task->pid != tmp->current_task->tid &&
					tmp->current_task->threadparent) {
				tmp->current_task->threadparent->threadstotalcpunsec += elapsed;
			}
		}
		tmp->task_start = end;
	}
}

void reset_perf_counter(gpointer key, gpointer value, gpointer user_data)
{
	((struct perfcounter*) value)->count = 0;
}

void copy_perf_counter(gpointer key, gpointer value, gpointer new_table)
{
	struct perfcounter *newperf;

	newperf = g_new0(struct perfcounter, 1);
	newperf->count = ((struct perfcounter *) value)->count;
	newperf->visible = ((struct perfcounter *) value)->visible;
	newperf->sort = ((struct perfcounter *) value)->sort;
	g_hash_table_insert((GHashTable *) new_table, strdup(key), newperf);
}

void copy_process_table(gpointer key, gpointer value, gpointer new_table)
{
	g_hash_table_insert((GHashTable *) new_table, key, value);
}

void rotate_perfcounter() {
	int i;
	struct processtop *tmp;

	for (i = 0; i < lttngtop.process_table->len; i++) {
		tmp = g_ptr_array_index(lttngtop.process_table, i);
		g_hash_table_foreach(tmp->perf, reset_perf_counter, NULL);
	}
}

void cleanup_processtop()
{
	gint i, j;
	struct processtop *tmp;
	struct files *tmpf; /* a temporary file */

	for (i = 0; i < lttngtop.process_table->len; i++) {
		tmp = g_ptr_array_index(lttngtop.process_table, i);
		tmp->totalcpunsec = 0;
		tmp->threadstotalcpunsec = 0;
		tmp->fileread = 0;
		tmp->filewrite = 0;

		for (j = 0; j < tmp->process_files_table->len; j++) {
			tmpf = g_ptr_array_index(tmp->process_files_table, j);
			if (tmpf != NULL) {
				tmpf->read = 0;
				tmpf->write = 0;

				if (tmpf->flag == __NR_close)
					g_ptr_array_index(
						tmp->process_files_table, j
					) = NULL;
			}
		}
	}
}

void reset_global_counters()
{
	lttngtop.nbnewproc = 0;
	lttngtop.nbdeadproc = 0;
	lttngtop.nbnewthreads = 0;
	lttngtop.nbdeadthreads = 0;
	lttngtop.nbnewfiles = 0;
	lttngtop.nbclosedfiles = 0;
}

void copy_global_counters(struct lttngtop *dst)
{
	dst->nbproc = lttngtop.nbproc;
	dst->nbnewproc = lttngtop.nbnewproc;
	dst->nbdeadproc = lttngtop.nbdeadproc;
	dst->nbthreads = lttngtop.nbthreads;
	dst->nbnewthreads = lttngtop.nbnewthreads;
	dst->nbdeadthreads = lttngtop.nbdeadthreads;
	dst->nbfiles = lttngtop.nbfiles;
	dst->nbnewfiles = lttngtop.nbnewfiles;
	dst->nbclosedfiles = lttngtop.nbclosedfiles;
	reset_global_counters();
}

struct lttngtop* get_copy_lttngtop(unsigned long start, unsigned long end)
{
	gint i, j;
	unsigned long time;
	struct lttngtop *dst;
	struct processtop *tmp, *tmp2, *new;
	struct cputime *tmpcpu, *newcpu;
	struct files *tmpfile, *newfile;
	struct kprobes *tmpprobe, *newprobe;

	dst = g_new0(struct lttngtop, 1);
	dst->start = start;
	dst->end = end;
	copy_global_counters(dst);
	dst->process_table = g_ptr_array_new();
	dst->files_table = g_ptr_array_new();
	dst->cpu_table = g_ptr_array_new();
	dst->kprobes_table = g_ptr_array_new();
	dst->process_hash_table = g_hash_table_new(g_direct_hash, g_direct_equal);
	g_hash_table_foreach(lttngtop.process_hash_table, copy_process_table,
			dst->process_hash_table);

	rotate_cputime(end);

	for (i = 0; i < lttngtop.process_table->len; i++) {
		tmp = g_ptr_array_index(lttngtop.process_table, i);
		new = g_new0(struct processtop, 1);

		memcpy(new, tmp, sizeof(struct processtop));
		new->threads = g_ptr_array_new();
		new->comm = strdup(tmp->comm);
		new->process_files_table = g_ptr_array_new();
		new->files_history = tmp->files_history;
		new->perf = g_hash_table_new(g_str_hash, g_str_equal);
		g_hash_table_foreach(tmp->perf, copy_perf_counter, new->perf);

		/* compute the stream speed */
		if (end - start != 0) {
			time = (end - start) / NSEC_PER_SEC;
			new->fileread = new->fileread/(time);
			new->filewrite = new->filewrite/(time);
		}

		for (j = 0; j < tmp->process_files_table->len; j++) {
			tmpfile = g_ptr_array_index(tmp->process_files_table, j);

			newfile = malloc(sizeof(struct files));

			if (tmpfile != NULL) {
				memcpy(newfile, tmpfile, sizeof(struct files));
				newfile->name = strdup(tmpfile->name);
				newfile->ref = new;
				g_ptr_array_add(new->process_files_table,
						newfile);
				g_ptr_array_add(dst->files_table, newfile);
			} else {
				g_ptr_array_add(new->process_files_table, NULL);
				g_ptr_array_add(dst->files_table, NULL);
			}
			/*
			 * if the process died during the last period, we remove all
			 * files associated with if after the copy
			 */
			if (tmp->death > 0 && tmp->death < end) {
				/* FIXME : close the files before */
				g_ptr_array_remove(tmp->process_files_table, tmpfile);
				g_free(tmpfile);
			}
		}
		g_ptr_array_add(dst->process_table, new);

		/*
		 * if the process died during the last period, we remove it from
		 * the current process list after the copy
		 */
		if (tmp->death > 0 && tmp->death < end) {
			g_ptr_array_remove(lttngtop.process_table, tmp);
			/* FIXME : TRUE does not mean clears the object in it */
			g_ptr_array_free(tmp->threads, TRUE);
			free(tmp->comm);
			g_ptr_array_free(tmp->process_files_table, TRUE);
			/* FIXME : clear elements */
			g_hash_table_destroy(tmp->perf);
			g_free(tmp);
		}
	}
	rotate_perfcounter();

	for (i = 0; i < lttngtop.cpu_table->len; i++) {
		tmpcpu = g_ptr_array_index(lttngtop.cpu_table, i);
		newcpu = g_new0(struct cputime, 1);
		memcpy(newcpu, tmpcpu, sizeof(struct cputime));
		newcpu->perf = g_hash_table_new(g_str_hash, g_str_equal);
		g_hash_table_foreach(tmpcpu->perf, copy_perf_counter, newcpu->perf);
		/*
		 * note : we don't care about the current process pointer in the copy
		 * so the reference is invalid after the memcpy
		 */
		g_ptr_array_add(dst->cpu_table, newcpu);
	}
	if (lttngtop.kprobes_table) {
		for (i = 0; i < lttngtop.kprobes_table->len; i++) {
			tmpprobe = g_ptr_array_index(lttngtop.kprobes_table, i);
			newprobe = g_new0(struct kprobes, 1);
			memcpy(newprobe, tmpprobe, sizeof(struct kprobes));
			tmpprobe->count = 0;
			g_ptr_array_add(dst->kprobes_table, newprobe);
		}
	}
	/* FIXME : better algo */
	/* create the threads index if required */
	for (i = 0; i < dst->process_table->len; i++) {
		tmp = g_ptr_array_index(dst->process_table, i);
		if (tmp->pid == tmp->tid) {
			for (j = 0; j < dst->process_table->len; j++) {
				tmp2 = g_ptr_array_index(dst->process_table, j);
				if (tmp2->pid == tmp->pid) {
					tmp2->threadparent = tmp;
					g_ptr_array_add(tmp->threads, tmp2);
				}
			}
		}
	}

	//  update_global_stats(dst);
	cleanup_processtop();

	return dst;
}


enum bt_cb_ret handle_statedump_process_state(struct bt_ctf_event *call_data,
		void *private_data)
{
	const struct bt_definition *scope;
	struct processtop *proc;
	unsigned long timestamp;
	int64_t pid, tid, ppid, vtid, vpid, vppid;
	char *procname, *hostname = NULL;

	timestamp = bt_ctf_get_timestamp(call_data);
	if (timestamp == -1ULL)
		goto error;

	scope = bt_ctf_get_top_level_scope(call_data,
			 BT_EVENT_FIELDS);
	pid = bt_ctf_get_int64(bt_ctf_get_field(call_data,
			     scope, "_pid"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing pid context info\n");
		goto error;
	}
	ppid = bt_ctf_get_int64(bt_ctf_get_field(call_data,
				scope, "_ppid"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing ppid context info\n");
		goto error;
	}
	tid = bt_ctf_get_int64(bt_ctf_get_field(call_data,
				scope, "_tid"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing tid context info\n");
		goto error;
	}
	vtid = bt_ctf_get_int64(bt_ctf_get_field(call_data,
				scope, "_vtid"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing vtid context info\n");
		goto error;
	}
	vpid = bt_ctf_get_int64(bt_ctf_get_field(call_data,
				scope, "_vpid"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing vpid context info\n");
		goto error;
	}
	vppid = bt_ctf_get_int64(bt_ctf_get_field(call_data,
				scope, "_vppid"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing vppid context info\n");
		goto error;
	}

	scope = bt_ctf_get_top_level_scope(call_data,
			BT_EVENT_FIELDS);
	procname = bt_ctf_get_char_array(bt_ctf_get_field(call_data,
				scope, "_name"));
	if (bt_ctf_field_get_error()) {
		fprintf(stderr, "Missing process name context info\n");
		goto error;
	}

	proc = find_process_tid(&lttngtop, tid, procname);
	if (proc == NULL)
		proc = add_proc(&lttngtop, tid, procname, timestamp, hostname);
	update_proc(proc, pid, tid, ppid, vpid, vtid, vppid, procname, hostname);

	if (proc) {
		free(proc->comm);
		proc->comm = strdup(procname);
		proc->pid = pid;
	}

	return BT_CB_OK;

error:
	return BT_CB_ERROR_STOP;
}

struct tm format_timestamp(uint64_t timestamp)
{
	struct tm tm;
	uint64_t ts_sec = 0, ts_nsec;
	time_t time_s;

	ts_nsec = timestamp;
	ts_sec += ts_nsec / NSEC_PER_SEC;
	ts_nsec = ts_nsec % NSEC_PER_SEC;

	time_s = (time_t) ts_sec;

	localtime_r(&time_s, &tm);

	return tm;
}

int *lookup_tid_list(int tid)
{
	if (!tid_filter_list)
		return NULL;

	return g_hash_table_lookup(tid_filter_list, (gpointer) &tid);
}

struct host *lookup_hostname_list(const char *hostname)
{
	if (!hostname || !global_host_list)
		return NULL;

	return g_hash_table_lookup(global_host_list, (gpointer) hostname);
}

int is_hostname_filtered(const char *hostname)
{
	struct host *host;

	host = lookup_hostname_list(hostname);
	if (host)
		return host->filter;
	return 0;
}

int *lookup_filter_tid_list(int tid)
{
	return g_hash_table_lookup(global_filter_list, (gpointer) &tid);
}

void add_filter_tid_list(struct processtop *proc)
{
	unsigned long *hash_tid;

	hash_tid = malloc(sizeof(unsigned long));
	*hash_tid = proc->tid;
	g_hash_table_insert(global_filter_list,
			(gpointer) (unsigned long) hash_tid, proc);
}

void remove_filter_tid_list(int tid)
{
	g_hash_table_remove(global_filter_list,
			(gpointer) (unsigned long) &tid);
}

struct host *add_hostname_list(char *hostname, int filter)
{
	struct host *host;

	host = lookup_hostname_list(hostname);
	if (host)
		return host;

	host = g_new0(struct host, 1);
	host->hostname = strdup(hostname);
	host->filter = filter;
	g_hash_table_insert(global_host_list,
			(gpointer) host->hostname,
			(gpointer) host);

	return host;
}

void update_hostname_filter(struct host *host)
{
	struct processtop *tmp;
	int i;

	for (i = 0; i < lttngtop.process_table->len; i++) {
		tmp = g_ptr_array_index(lttngtop.process_table, i);
		if (tmp->host == host) {
			if (host->filter)
				add_filter_tid_list(tmp);
			else
				remove_filter_tid_list(tmp->tid);
		}
	}
}

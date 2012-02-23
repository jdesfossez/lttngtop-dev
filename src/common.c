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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include <stdlib.h>
#include <string.h>
#include "common.h"

struct processtop *find_process_tid(struct lttngtop *ctx, int tid, char *comm)
{
	gint i;
	struct processtop *tmp;

	for (i = 0; i < ctx->process_table->len; i++) {
		tmp = g_ptr_array_index(ctx->process_table, i);
		if (tmp && tmp->tid == tid)
			return tmp;
	}
	return NULL;
}

struct processtop* add_proc(struct lttngtop *ctx, int tid, char *comm,
		unsigned long timestamp)
{
	struct processtop *newproc;

	/* if the PID already exists, we just rename the process */
	/* FIXME : need to integrate with clone/fork/exit to be accurate */
	newproc = find_process_tid(ctx, tid, comm);
	if (!newproc) {
		newproc = g_new0(struct processtop, 1);
		newproc->tid = tid;
		newproc->birth = timestamp;
		newproc->process_files_table = g_ptr_array_new();
		newproc->files_history = g_new0(struct file_history, 1);
		newproc->files_history->next = NULL;
		newproc->totalfileread = 0;
		newproc->totalfilewrite = 0;
		newproc->fileread = 0;
		newproc->filewrite = 0;
		newproc->syscall_info = NULL;
		newproc->threads = g_ptr_array_new();
		newproc->perf = g_hash_table_new(g_str_hash, g_str_equal);
		g_ptr_array_add(ctx->process_table, newproc);
	}
	newproc->comm = strdup(comm);

	return newproc;
}

struct processtop* update_proc(struct processtop* proc, int pid, int tid,
		int ppid, char *comm)
{
	if (proc) {
		proc->pid = pid;
		proc->tid = tid;
		proc->ppid = ppid;
		if (strcmp(proc->comm, comm) != 0) {
			free(proc->comm);
			proc->comm = strdup(comm);
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
	if (tmp && strcmp(tmp->comm, comm) == 0)
		tmp->death = timestamp;
}

struct processtop* get_proc(struct lttngtop *ctx, int tid, char *comm,
		unsigned long timestamp)
{
	struct processtop *tmp;
	tmp = find_process_tid(ctx, tid, comm);
	if (tmp && strcmp(tmp->comm, comm) == 0)
		return tmp;
	return add_proc(ctx, tid, comm, timestamp);
}

void add_thread(struct processtop *parent, struct processtop *thread)
{
	gint i;
	struct processtop *tmp;

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
			}
		}
	}
}

struct lttngtop* get_copy_lttngtop(unsigned long start, unsigned long end)
{
	gint i, j;
	unsigned long time;
	struct lttngtop *dst;
	struct processtop *tmp, *tmp2, *new;
	struct cputime *tmpcpu, *newcpu;
	struct files *tmpfile, *newfile;

	dst = g_new0(struct lttngtop, 1);
	dst->start = start;
	dst->end = end;
	dst->process_table = g_ptr_array_new();
	dst->files_table = g_ptr_array_new();
	dst->cpu_table = g_ptr_array_new();
	dst->perf_list = g_hash_table_new(g_str_hash, g_str_equal);

	rotate_cputime(end);

	g_hash_table_foreach(lttngtop.perf_list, copy_perf_counter, dst->perf_list);
	for (i = 0; i < lttngtop.process_table->len; i++) {
		tmp = g_ptr_array_index(lttngtop.process_table, i);
		new = g_new0(struct processtop, 1);

		memcpy(new, tmp, sizeof(struct processtop));
		new->threads = g_ptr_array_new();
		new->comm = strdup(tmp->comm);
		new->process_files_table = g_ptr_array_new();
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


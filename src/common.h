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

#ifndef _COMMON_H
#define _COMMON_H

#include <semaphore.h>
#include <babeltrace/ctf/events.h>
#include "lttngtoptypes.h"
#include "cputop.h"

#define NSEC_PER_USEC 1000
#define NSEC_PER_SEC 1000000000L

sem_t goodtodisplay, goodtoupdate, timer, pause_sem, end_trace_sem, bootstrap;

GPtrArray *copies; /* struct lttngtop */
GHashTable *global_perf_liszt;

struct lttngtop *data;

struct processtop *find_process_tid(struct lttngtop *ctx, int pid, char *comm);
struct processtop* add_proc(struct lttngtop *ctx, int pid, char *comm,
		unsigned long timestamp);
struct processtop* update_proc(struct processtop* proc, int pid, int tid,
		int ppid, char *comm);
void add_thread(struct processtop *parent, struct processtop *thread);
struct processtop* get_proc(struct lttngtop *ctx, int tid, char *comm,
		unsigned long timestamp);

struct processtop *get_proc_pid(struct lttngtop *ctx, int tid, int pid,
		unsigned long timestamp);

void death_proc(struct lttngtop *ctx, int tid, char *comm,
		unsigned long timestamp);
struct cputime* add_cpu(int cpu);
struct cputime* get_cpu(int cpu);
struct lttngtop* get_copy_lttngtop(unsigned long start, unsigned long end);
struct perfcounter *add_perf_counter(GPtrArray *perf, GQuark quark,
		unsigned long count);
struct perfcounter *get_perf_counter(const char *name, struct processtop *proc,
		struct cputime *cpu);
void reset_global_counters(void);

/* common field access functions */
uint64_t get_cpu_id(const struct bt_ctf_event *event);
uint64_t get_context_tid(const struct bt_ctf_event *event);
uint64_t get_context_pid(const struct bt_ctf_event *event);
uint64_t get_context_ppid(const struct bt_ctf_event *event);
char *get_context_comm(const struct bt_ctf_event *event);

enum bt_cb_ret handle_statedump_process_state(struct bt_ctf_event *call_data,
					      void *private_data);

#endif /* _COMMON_H */

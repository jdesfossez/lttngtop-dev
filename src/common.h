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
GHashTable *global_filter_list;
GHashTable *global_host_list;

char *opt_tid;
char *opt_hostname;
char *opt_relay_hostname;
char *opt_kprobes;
GHashTable *tid_filter_list;

int remote_live;

int toggle_filter;

extern int quit;

struct lttngtop *data;

struct processtop *find_process_tid(struct lttngtop *ctx, int pid, char *comm);
struct processtop* add_proc(struct lttngtop *ctx, int pid, char *comm,
		unsigned long timestamp, char *hostname);
struct processtop* update_proc(struct processtop* proc, int pid, int tid,
		int ppid, int vpid, int vtid, int vppid, char *comm,
		char *hostname);
void add_thread(struct processtop *parent, struct processtop *thread);
struct processtop* get_proc(struct lttngtop *ctx, int tid, char *comm,
		unsigned long timestamp, char *hostname);

struct processtop *get_proc_pid(struct lttngtop *ctx, int tid, int pid,
		unsigned long timestamp, char *hostname);

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
uint64_t get_context_vtid(const struct bt_ctf_event *event);
uint64_t get_context_vpid(const struct bt_ctf_event *event);
uint64_t get_context_vppid(const struct bt_ctf_event *event);
char *get_context_hostname(const struct bt_ctf_event *event);

enum bt_cb_ret handle_statedump_process_state(struct bt_ctf_event *call_data,
					      void *private_data);

struct tm format_timestamp(uint64_t timestamp);

int *lookup_filter_tid_list(int tid);
int *lookup_tid_list(int tid);
void remove_hostname_list(const char *hostname);
void add_filter_tid_list(struct processtop *proc);
void remove_filter_tid_list(int tid);
struct host *lookup_hostname_list(const char *hostname);
int is_hostname_filtered(const char *hostname);
struct host *add_hostname_list(char *hostname, int filter);
void update_hostname_filter(struct host *host);

#endif /* _COMMON_H */

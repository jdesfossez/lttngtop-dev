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

#ifndef LTTNGTOPTYPES_H
#define LTTNGTOPTYPES_H

#include <glib.h>

struct lttngtop {
	GPtrArray *process_table;	/* struct processtop */
	GPtrArray *files_table;		/* struct files */
	GPtrArray *cpu_table;		/* struct cputime */
	GHashTable *perf_list;		/* struct perfcounter */
	unsigned long start;
	unsigned long end;
	unsigned int nbproc;
	unsigned int nbnewproc;
	unsigned int nbdeadproc;
	unsigned int nbthreads;
	unsigned int nbnewthreads;
	unsigned int nbdeadthreads;
	unsigned int nbfiles;
	unsigned int nbnewfiles;
	unsigned int nbclosedfiles;
} lttngtop;

struct processtop {
	unsigned int puuid;
	int pid;
	char *comm;
	int tid;
	int ppid;
	int oldpid;
	int oldtid;
	int oldppid;
	unsigned long birth;
	unsigned long death;
	unsigned long lastactivity;
	GPtrArray *process_files_table;
	GPtrArray *threads;
	GHashTable *perf;
	struct processtop *threadparent;
	unsigned long totalfileread;
	unsigned long totalfilewrite;
	unsigned long totalcpunsec;
	unsigned long threadstotalcpunsec;
	/* IO speed for this process */
	struct iostream *iostream;
};

struct perfcounter
{
	unsigned long count;
	int visible;
	int sort;
};

struct cputime {
	guint id;
	struct processtop *current_task;
	unsigned long task_start;
	GHashTable *perf;
};

/*
 * used for "relative seeks" (with fd, for example fs.lseek)
 * and for "absolute seeks" (events occuring on a device without
 * any link to a particular process)
 */
struct seeks {
	unsigned long offset;
	unsigned long count;
};

struct ioctls {
	unsigned int command;
	unsigned long count;
};

struct files {
	struct processtop *ref;
	unsigned int fuuid;
	int fd;
	char *name;
	int oldfd;
	int device;
	int openmode;
	unsigned long openedat;
	unsigned long closedat;
	unsigned long lastaccess;
	unsigned long read;
	unsigned long write;
	unsigned long nbpoll;
	unsigned long nbselect;
	unsigned long nbopen;
	unsigned long nbclose;
	//struct *seeks; /* relative seeks inside the file */
	//struct *ioctls;
	/* XXX : average wait time */
};

struct sockets {
	int fd;
	int parent_fd;  /* on accept a new fd is created from the bound socket */
	int family;
	int type;
	int protocol;
	int sock_address;
	unsigned long openedat;
	unsigned long closedat;
	unsigned long bind_address;
	unsigned long remote_address;
	//struct *sock_options;
};

struct sock_options {
	int name;
	int value;
};

struct vmas {
	unsigned long start;
	unsigned long end;
	unsigned long flags;
	unsigned long prot;
	char *description; /* filename or description if possible (stack, heap) */
	unsigned long page_faults;
};

struct syscalls {
	unsigned int id;
	unsigned long count;
        unsigned int cpu_id;
        unsigned int type;
        unsigned int tid;
};

struct signals {
	int dest_pid;
	int id;
	unsigned long count;
};

struct iostream {
        struct syscalls *syscall_info; /* NULL if there is no waiting for an exit_syscall */
        unsigned long ret_read;        /* value returned by an I/O syscall_exit for a sys_read*/
        unsigned long ret_write;       /* value returned by an I/O syscall_exit for a sys_write*/
        unsigned long ret_total;
};

#endif /* LTTNGTOPTYPES_H */

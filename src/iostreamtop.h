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

#ifndef _IOSTREANTOP_H
#define _IOSTREAMTOP_H

#include <babeltrace/babeltrace.h>
#include <babeltrace/ctf/events.h>
#include <inttypes.h>
#include <glib.h>
#include <asm/unistd.h>

struct files *get_file(struct processtop *proc, int fd);
void show_table(GPtrArray *tab);
void insert_file(struct processtop *proc, int fd);

enum bt_cb_ret handle_exit_syscall(struct bt_ctf_event *call_data,
		void *private_data);
enum bt_cb_ret handle_sys_write(struct bt_ctf_event *call_data,
		void *private_data);
enum bt_cb_ret handle_sys_read(struct bt_ctf_event *call_data,
		void *private_data);
enum bt_cb_ret handle_sys_open(struct bt_ctf_event *call_data,
		void *private_data);
enum bt_cb_ret handle_sys_close(struct bt_ctf_event *call_data,
		void *private_data);
enum bt_cb_ret handle_statedump_file_descriptor(struct bt_ctf_event *call_data,
		void *private_data);

#endif /* _IOSTREAMTOP_H */

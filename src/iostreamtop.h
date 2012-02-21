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

#ifndef _IOSTREANTOP_H
#define _IOSTREAMTOP_H

#include <babeltrace/babeltrace.h>
#include <inttypes.h>
#include <glib.h>
#include <asm/unistd.h>

/*
#define SYS_READ  1
#define SYS_WRITE 2
*/

enum bt_cb_ret handle_exit_syscall(struct bt_ctf_event *call_data,
		void *private_data);

enum bt_cb_ret handle_sys_write(struct bt_ctf_event *call_data,
		void *private_data);

enum bt_cb_ret handle_sys_read(struct bt_ctf_event *call_data,
		void *private_data);

#endif /* _IOSTREAMTOP_H */

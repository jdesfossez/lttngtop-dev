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

#ifndef _LTTNGTOP_H
#define _LTTNGTOP_H

#include <babeltrace/babeltrace.h>
#include <babeltrace/ctf/callbacks.h>
#include <inttypes.h>
#include <glib.h>

enum bt_cb_ret handle_sched_switch(struct bt_ctf_event *hook_data,
		void *call_data);

enum bt_cb_ret handle_sched_process_free(struct bt_ctf_event *call_data,
		void *private_data);

#endif /* _LTTNGTOP_H */

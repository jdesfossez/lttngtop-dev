/*
 * Copyright (C) 2013 Julien Desfossez <jdesfossez@efficios.com>
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

#ifndef _LIVE_H
#define _LIVE_H

int mmap_live_loop(struct bt_context *bt_ctx,
		struct bt_mmap_stream_list mmap_list);
void mmap_live_flush(struct bt_mmap_stream_list mmap_list);

#endif /* _LIVE_H */

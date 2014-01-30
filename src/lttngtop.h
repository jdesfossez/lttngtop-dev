/*
 * Copyright (C) 2014 Julien Desfossez
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

#ifndef LTTNGTOP_H
#define LTTNGTOP_H

int check_requirements(struct bt_context *ctx);
extern int opt_textdump;
extern int opt_child;
extern int opt_begin;

extern pthread_t display_thread;
extern pthread_t timer_thread;
void *ncurses_display(void *p);
void *refresh_thread(void *p);
void iter_trace(struct bt_context *bt_ctx);

#endif /* LTTNGTOP_H */

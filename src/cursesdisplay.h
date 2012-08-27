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

#ifndef CURSESDISPLAY_H
#define CURSESDISPLAY_H

#include <glib.h>
#include <ncurses.h>
#include "common.h"

enum view_list
{
	cpu = 1,
	perf,
	process_details,
	iostream,
	tree,
	kprobes,
};

enum view_list current_view;
enum view_list previous_view;

void display(unsigned int);
void init_ncurses();
void reset_ncurses();

#endif // CURSESDISPLAY_H

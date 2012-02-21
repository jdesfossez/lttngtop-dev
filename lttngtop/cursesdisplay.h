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

#ifndef CURSESDISPLAY_H
#define CURSESDISPLAY_H

#include <glib.h>
#include <ncurses.h>
#include "common.h"

enum current_view_list
{
	cpu = 1,
	perf,
	process_details,
	fileio,
	netio,
	iostream,
	tree,
} current_view;

void display(unsigned int);
void init_ncurses();
void reset_ncurses();

#endif // CURSESDISPLAY_H

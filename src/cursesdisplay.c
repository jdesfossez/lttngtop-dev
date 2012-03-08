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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <ncurses.h>
#include <panel.h>
#include <pthread.h>
#include <semaphore.h>

#include "cursesdisplay.h"
#include "lttngtoptypes.h"
#include "iostreamtop.h"
#include "common.h"

#define DEFAULT_DELAY 15
#define MAX_LINE_LENGTH 50
#define MAX_LOG_LINES 4

/* to prevent concurrent updates of the different windows */
sem_t update_display_sem;

char *termtype;
WINDOW *footer, *header, *center, *status;
WINDOW *perf_panel_window = NULL;
PANEL *perf_panel, *main_panel;

int perf_panel_visible = 0;
int perf_line_selected = 0;

int last_display_index, currently_displayed_index;

struct processtop *selected_process = NULL;
int selected_tid;
char *selected_comm;
int selected_ret;

int selected_line = 0; /* select bar position */
int selected_in_list = 0; /* selection relative to the whole list */
int list_offset = 0; /* first index in the list to display (scroll) */
int nb_log_lines = 0;
char log_lines[MAX_LINE_LENGTH * MAX_LOG_LINES + MAX_LOG_LINES];

int max_elements = 80;

int toggle_threads = -1;
int toggle_pause = -1;
int toggle_tree = -1;

int max_center_lines;

pthread_t keyboard_thread;

void reset_ncurses()
{
	curs_set(1);
	endwin();
	exit(0);
}

static void handle_sigterm(int signal)
{
	reset_ncurses();
}

void init_screen()
{
	initscr();
	noecho();
	halfdelay(DEFAULT_DELAY);
	nonl();
	intrflush(stdscr, false);
	keypad(stdscr, true);
	curs_set(0);

	if (has_colors()) {
		start_color();
		init_pair(1, COLOR_RED, COLOR_BLACK); /* - */
		init_pair(2, COLOR_GREEN, COLOR_BLACK); /* + */
		init_pair(3, COLOR_BLACK, COLOR_WHITE); /* keys */
		init_pair(4, COLOR_WHITE, COLOR_GREEN); /* keys activated */
		init_pair(5, COLOR_WHITE, COLOR_BLUE); /* select line */
	}
	termtype = getenv("TERM");
	if (!strcmp(termtype, "xterm") ||  !strcmp(termtype, "xterm-color") ||
			!strcmp(termtype, "vt220")) {
		define_key("\033[H", KEY_HOME);
		define_key("\033[F", KEY_END);
		define_key("\033OP", KEY_F(1));
		define_key("\033OQ", KEY_F(2));
		define_key("\033OR", KEY_F(3));
		define_key("\033OS", KEY_F(4));
		define_key("\0330U", KEY_F(6));
		define_key("\033[11~", KEY_F(1));
		define_key("\033[12~", KEY_F(2));
		define_key("\033[13~", KEY_F(3));
		define_key("\033[14~", KEY_F(4));
		define_key("\033[16~", KEY_F(6));
		define_key("\033[17;2~", KEY_F(18));
	}
	signal(SIGTERM, handle_sigterm);
	mousemask(BUTTON1_CLICKED, NULL);
	refresh();
}

WINDOW *create_window(int height, int width, int startx, int starty)
{
	WINDOW *win;
	win = newwin(height, width, startx, starty);
	box(win, 0 , 0);
	wrefresh(win);
	return win;
}

WINDOW *create_window_no_border(int height, int width, int startx, int starty)
{
	WINDOW *win;
	win = newwin(height, width, startx, starty);
	wrefresh(win);
	return win;
}

void print_digit(WINDOW *win, int digit)
{
	if (digit < 0) {
		wattron(win, COLOR_PAIR(1));
		wprintw(win, "%d", digit);
		wattroff(win, COLOR_PAIR(1));
	} else if (digit > 0) {
		wattron(win, COLOR_PAIR(2));
		wprintw(win, "+%d", digit);
		wattroff(win, COLOR_PAIR(2));
	} else {
		wprintw(win, "0");
	}
}

void print_digits(WINDOW *win, int first, int second)
{
	wprintw(win, "(");
	print_digit(win, first);
	wprintw(win, ", ");
	print_digit(win, second);
	wprintw(win, ")");
}

void print_headers(int line, char *desc, int value, int first, int second)
{
	wattron(header, A_BOLD);
	mvwprintw(header, line, 4, "%s", desc);
	wattroff(header, A_BOLD);
	mvwprintw(header, line, 16, "N/A", value);
	wmove(header, line, 24);
	print_digits(header, first, second);
	wmove(header, line, 40);
}

void set_window_title(WINDOW *win, char *title)
{
	wattron(win, A_BOLD);
	mvwprintw(win, 0, 1, title);
	wattroff(win, A_BOLD);
}

void print_log(char *str)
{
	int i;
	int current_line = 1;
	int current_char = 1;
	char *tmp, *tmp2;
	/* rotate the line buffer */
	if (nb_log_lines >= MAX_LOG_LINES) {
		tmp = strndup(log_lines, MAX_LINE_LENGTH * MAX_LOG_LINES + MAX_LOG_LINES);
		tmp2 = strchr(tmp, '\n');
		memset(log_lines, '\0', strlen(log_lines));
		strncat(log_lines, tmp2 + 1, strlen(tmp2) - 1);
		log_lines[strlen(log_lines)] = '\n';
		log_lines[strlen(log_lines)] = '\0';
		free(tmp);
	}
	nb_log_lines++;

	strncat(log_lines, str, MAX_LINE_LENGTH - 1);

	if (nb_log_lines < MAX_LOG_LINES)
		log_lines[strlen(log_lines)] = '\n';
	log_lines[strlen(log_lines)] = '\0';

	werase(status);
	box(status, 0 , 0);
	set_window_title(status, "Status");
	for (i = 0; i < strlen(log_lines); i++) {
		if (log_lines[i] == '\n') {
			wmove(status, ++current_line, 1);
			current_char = 1;
		} else {
			mvwprintw(status, current_line, current_char++, "%c",
					log_lines[i]);
		}
	}
	wrefresh(status);
}

void print_key(WINDOW *win, char *key, char *desc, int toggle)
{
	int pair;
	if (toggle > 0)
		pair = 4;
	else
		pair = 3;
	wattron(win, COLOR_PAIR(pair));
	wprintw(footer, "%s", key);
	wattroff(win, COLOR_PAIR(pair));
	wprintw(footer, ":%s", desc);
}

void update_footer()
{
	sem_wait(&update_display_sem);
	werase(footer);
	wmove(footer, 1, 1);
	print_key(footer, "F2", "CPUtop  ", current_view == cpu);
	print_key(footer, "F3", "PerfTop  ", current_view == perf);
	print_key(footer, "F6", "IOTop  ", current_view == iostream);
	print_key(footer, "Enter", "Details  ", current_view == process_details);
	print_key(footer, "q", "Quit | ", 0);
	print_key(footer, "P", "Perf Pref  ", 0);
	print_key(footer, "p", "Pause  ", toggle_pause);

	wrefresh(footer);
	sem_post(&update_display_sem);
}

void basic_header()
{
	werase(header);
	box(header, 0 , 0);
	set_window_title(header, "Statistics for interval [gathering data...[");
	wattron(header, A_BOLD);
	mvwprintw(header, 1, 4, "CPUs");
	mvwprintw(header, 2, 4, "Processes");
	mvwprintw(header, 3, 4, "Threads");
	mvwprintw(header, 4, 4, "Files");
	mvwprintw(header, 5, 4, "Network");
	mvwprintw(header, 6, 4, "IO");
	wattroff(header, A_BOLD);
	wrefresh(header);
}

void update_header()
{
	werase(header);
	box(header, 0 , 0);
	set_window_title(header, "Statistics for interval ");
	wattron(header, A_BOLD);
	/*
	wprintw(header, "[%lu.%lu, %lu.%lu[",
			data->start.tv_sec, data->start.tv_nsec,
			data->end.tv_sec, data->end.tv_nsec);
			*/
	wprintw(header, "[%lu, %lu[",
            data->start,
            data->end);
	mvwprintw(header, 1, 4, "CPUs");
	wattroff(header, A_BOLD);
	wprintw(header, "\t%d\t(max/cpu : %0.2f%)", data->cpu_table->len,
			100.0/data->cpu_table->len);
	print_headers(2, "Processes", data->nbproc, data->nbnewproc,
			-1*(data->nbdeadproc));
	print_headers(3, "Threads", data->nbthreads, data->nbnewthreads,
			-1*(data->nbdeadthreads));
	print_headers(4, "Files", data->nbfiles, data->nbnewfiles,
			-1*(data->nbclosedfiles));
	mvwprintw(header, 4, 43, "N/A kbytes/sec");
	print_headers(5, "Network", 114, 0, 0);
	mvwprintw(header, 5, 43, "N/A Mbytes/sec");
	wrefresh(header);
}

gint sort_by_cpu_desc(gconstpointer p1, gconstpointer p2)
{
	struct processtop *n1 = *(struct processtop **)p1;
	struct processtop *n2 = *(struct processtop **)p2;
	unsigned long totaln1 = n1->totalcpunsec;
	unsigned long totaln2 = n2->totalcpunsec;

	if (totaln1 < totaln2)
		return 1;
	if (totaln1 == totaln2)
		return 0;
	return -1;
}

gint sort_by_cpu_group_by_threads_desc(gconstpointer p1, gconstpointer p2)
{
	struct processtop *n1 = *(struct processtop **)p1;
	struct processtop *n2 = *(struct processtop **)p2;
	unsigned long totaln1 = n1->threadstotalcpunsec;
	unsigned long totaln2 = n2->threadstotalcpunsec;

	if (totaln1 < totaln2)
		return 1;
	if (totaln1 == totaln2)
		return 0;
	return -1;
}

void update_cputop_display()
{
	int i;
	int header_offset = 2;
	struct processtop *tmp;
	unsigned long elapsed;
	double maxcputime;
	int nblinedisplayed = 0;
	int current_line = 0;

	elapsed = data->end - data->start;
	maxcputime = elapsed * data->cpu_table->len / 100.0;

	g_ptr_array_sort(data->process_table, sort_by_cpu_desc);

	set_window_title(center, "CPU Top");
	wattron(center, A_BOLD);
	mvwprintw(center, 1, 1, "CPU(%)");
	mvwprintw(center, 1, 12, "TGID");
	mvwprintw(center, 1, 22, "PID");
	mvwprintw(center, 1, 32, "NAME");
	wattroff(center, A_BOLD);

	max_center_lines = LINES - 7 - 7 - 1 - header_offset;

	/* iterate the process (thread) list */
	for (i = list_offset; i < data->process_table->len &&
			nblinedisplayed < max_center_lines; i++) {
		tmp = g_ptr_array_index(data->process_table, i);

		if (current_line == selected_line) {
			selected_process = tmp;
			selected_tid = tmp->tid;
			selected_comm = tmp->comm;
			wattron(center, COLOR_PAIR(5));
			mvwhline(center, current_line + header_offset, 1, ' ', COLS-3);
		}
		/* CPU(%) */
		mvwprintw(center, current_line + header_offset, 1, "%1.2f",
				tmp->totalcpunsec / maxcputime);
		/* TGID */
		mvwprintw(center, current_line + header_offset, 12, "%d", tmp->pid);
		/* PID */
		mvwprintw(center, current_line + header_offset, 22, "%d", tmp->tid);
		/* NAME */
		mvwprintw(center, current_line + header_offset, 32, "%s", tmp->comm);
		wattroff(center, COLOR_PAIR(5));
		nblinedisplayed++;
		current_line++;
	}
}

gint sort_perf(gconstpointer p1, gconstpointer p2, gpointer key)
{
	struct processtop *n1 = *(struct processtop **) p1;
	struct processtop *n2 = *(struct processtop **) p2;

	struct perfcounter *tmp1, *tmp2;
	unsigned long totaln2 = 0;
	unsigned long totaln1 = 0;

	if (!key)
		return 0;

	tmp1 = g_hash_table_lookup(n1->perf, key);
	if (!tmp1)
		totaln1 = 0;
	else
		totaln1 = tmp1->count;

	tmp2 = g_hash_table_lookup(n2->perf, key);
	if (!tmp2)
		totaln2 = 0;
	else
		totaln2 = tmp2->count;

	if (totaln1 < totaln2)
		return 1;
	if (totaln1 == totaln2) {
		totaln1 = n1->tid;
		totaln2 = n2->tid;
		if (totaln1 < totaln2)
			return 1;
		return -1;
	}
	return -1;
}

void print_key_title(char *key, int line)
{
	wattron(center, A_BOLD);
	mvwprintw(center, line, 1, "%s\t", key);
	wattroff(center, A_BOLD);
}

void update_process_details()
{
	unsigned long elapsed;
	double maxcputime;
	struct processtop *tmp = find_process_tid(data, selected_tid, selected_comm);
	struct files *file_tmp;
	int i, j = 0;

	set_window_title(center, "Process details");


	elapsed = data->end - data->start;
	maxcputime = elapsed * data->cpu_table->len / 100.0;

	print_key_title("Name", 1);
	wprintw(center, "%s", selected_comm);
	print_key_title("TID", 2);
	wprintw(center, "%d", selected_tid);
	if (!tmp) {
		print_key_title("Does not exit at this time", 3);
		return;
	}

	print_key_title("PID", 3);
	wprintw(center, "%d", tmp->pid);
	print_key_title("PPID", 4);
	wprintw(center, "%d", tmp->ppid);
	print_key_title("CPU", 5);
	wprintw(center, "%1.2f %%", tmp->totalcpunsec/maxcputime);

	print_key_title("READ B/s", 6);
	wprintw(center, "%d", tmp->fileread);

	print_key_title("WRITE B/s", 7);
	wprintw(center, "%d", tmp->filewrite);

	for (i = 0; i < tmp->process_files_table->len; i++) {
		file_tmp = get_file(tmp, i);
		if (file_tmp != NULL) {
			print_key_title("file", 8+j);
			wprintw(center, "%s fd = %d", file_tmp->name, i);
			wprintw(center, " read = %d", file_tmp->read);
			wprintw(center, " write = %d", file_tmp->write);
			j++;
		}
	}
}

void update_perf()
{
	int i;
	int nblinedisplayed = 0;
	int current_line = 0;
	struct processtop *tmp;
	int header_offset = 2;
	int perf_row = 40;
	struct perfcounter *perfn1, *perfn2;
	char *perf_key = NULL;
	int value;
	GHashTableIter iter;
	gpointer key;

	set_window_title(center, "Perf Top");
	wattron(center, A_BOLD);
	mvwprintw(center, 1, 1, "PID");
	mvwprintw(center, 1, 11, "TID");
	mvwprintw(center, 1, 22, "NAME");

	perf_row = 40;
	g_hash_table_iter_init(&iter, data->perf_list);
	while (g_hash_table_iter_next (&iter, &key, (gpointer) &perfn1)) {
		if (perfn1->visible) {
			/* + 5 to strip the "perf_" prefix */
			mvwprintw(center, 1, perf_row, "%s",
					(char *) key + 5);
			perf_row += 20;
		}
		if (perfn1->sort) {
			perf_key = (char *) key;
		}
	}

	wattroff(center, A_BOLD);

	g_ptr_array_sort_with_data(data->process_table, sort_perf, perf_key);

	for (i = 0; i < data->process_table->len && 
			nblinedisplayed < max_center_lines; i++) {
		tmp = g_ptr_array_index(data->process_table, i);

		if (current_line == selected_line) {
			selected_process = tmp;
			wattron(center, COLOR_PAIR(5));
			mvwhline(center, current_line + header_offset, 1, ' ', COLS-3);
		}

		mvwprintw(center, current_line + header_offset, 1, "%d", tmp->pid);
		mvwprintw(center, current_line + header_offset, 11, "%d", tmp->tid);
		mvwprintw(center, current_line + header_offset, 22, "%s", tmp->comm);

		g_hash_table_iter_init(&iter, data->perf_list);

		perf_row = 40;
		while (g_hash_table_iter_next (&iter, &key, (gpointer) &perfn1)) {
			if (perfn1->visible) {
				perfn2 = g_hash_table_lookup(tmp->perf, (char *) key);
				if (perfn2)
					value = perfn2->count;
				else
					value = 0;
				mvwprintw(center, current_line + header_offset,
						perf_row, "%d", value);
				perf_row += 20;
			}
		}

		wattroff(center, COLOR_PAIR(5));
		nblinedisplayed++;
		current_line++;
	}
}

void update_fileio()
{
	int i;
	int offset;

	set_window_title(center, "IO Top");
	wattron(center, A_BOLD);
	mvwprintw(center, 1, 10, "READ");
	mvwprintw(center, 2, 1, "bytes");
	mvwprintw(center, 2, 15, "bytes/sec");

	mvwprintw(center, 1, 39, "WRITE");
	mvwprintw(center, 2, 33, "bytes");
	mvwprintw(center, 2, 45, "bytes/sec");

	if (toggle_threads > 0) {
		mvwprintw(center, 1, 60, "TGID");
		mvwprintw(center, 1, 70, "PID");
		offset = 8;
	} else {
		mvwprintw(center, 1, 60, "PID(TGID)");
		offset = 0;
	}
	mvwprintw(center, 1, 72 + offset, "NAME");
	wattroff(center, A_BOLD);

	for (i = 3; i < LINES - 3 - 8 - 1; i++) {
		mvwprintw(center, i, 1, "%d", i*1000);
		mvwprintw(center, i, 15, "%dk", i);
		mvwprintw(center, i, 28, "|    %d", i*2000);
		mvwprintw(center, i, 45, "%dk", i*2);
		if (toggle_threads > 0) {
			mvwprintw(center, i, 57, "|  %d", i);
			mvwprintw(center, i, 70, "%d", i);
		} else {
			mvwprintw(center, i, 57, "|  %d", i);
		}
		mvwprintw(center, i, 72 + offset, "process_%d", i);
	}
}

gint sort_by_ret_desc(gconstpointer p1, gconstpointer p2)
{
	struct processtop *n1 = *(struct processtop **)p1;
	struct processtop *n2 = *(struct processtop **)p2;

	unsigned long totaln1 = n1->totalfileread + n1->totalfilewrite;
	unsigned long totaln2 = n2->totalfileread + n2->totalfilewrite;

	if (totaln1 < totaln2)
		return 1;
	if (totaln1 == totaln2)
		return 0;
	return -1;
}

void update_iostream()
{
	int i;
	int header_offset = 2;
	struct processtop *tmp;
	int nblinedisplayed = 0;
	int current_line = 0;
	int total = 0;

	set_window_title(center, "IO Top");
	wattron(center, A_BOLD);
	mvwprintw(center, 1, 1, "READ (B/s)");
	mvwprintw(center, 1, 20, "WRITE (B/s)");

	mvwprintw(center, 1, 40, "TOTAL STREAM");

	mvwprintw(center, 1, 60, "TGID");
	mvwprintw(center, 1, 80, "PID");

	mvwprintw(center, 1, 92, "NAME");
	wattroff(center, A_BOLD);

	g_ptr_array_sort(data->process_table, sort_by_ret_desc);

	for (i = list_offset; i < data->process_table->len &&
			nblinedisplayed < max_center_lines; i++) {
		tmp = g_ptr_array_index(data->process_table, i);

		if (current_line == selected_line) {
			selected_process = tmp;
			selected_tid = tmp->tid;
			selected_comm = tmp->comm;
			wattron(center, COLOR_PAIR(5));
			mvwhline(center, current_line + header_offset, 1, ' ', COLS-3);
		}

		/* READ (bytes/sec) */
		mvwprintw(center, current_line + header_offset, 1, "%lu",
			tmp->fileread);

		/* WRITE (bytes/sec) */
		mvwprintw(center, current_line + header_offset, 20, "%lu",
			tmp->filewrite);

		/* TOTAL STREAM */
		total = tmp->totalfileread + tmp->totalfilewrite;

		if (total >= 1000000)
			mvwprintw(center, current_line + header_offset, 40, "%lu MB",
					total/1000000);
		else if (total >= 1000)
			mvwprintw(center, current_line + header_offset, 40, "%lu KB",
					total/1000);
		else
			mvwprintw(center, current_line + header_offset, 40, "%lu B",
					total);

		/* TGID */
		mvwprintw(center, current_line + header_offset, 60, "%d", tmp->pid);
		/* PID */
		mvwprintw(center, current_line + header_offset, 80, "%d", tmp->tid);
		/* NAME */
		mvwprintw(center, current_line + header_offset, 92, "%s", tmp->comm);
		wattroff(center, COLOR_PAIR(5));
		nblinedisplayed++;
		current_line++;
	}
}

void update_current_view()
{
	sem_wait(&update_display_sem);
	if (!data)
		return;
	update_header();

	werase(center);
	box(center, 0, 0);
	switch (current_view) {
	case cpu:
		update_cputop_display();
		break;
	case perf:
		update_perf();
		break;
	case process_details:
		update_process_details();
		break;
	case fileio:
		update_fileio();
		break;
	case iostream:
		update_iostream();
		break;
	case tree:
		update_cputop_display();
		break;
	default:
		break;
	}
	update_panels();
	doupdate();
	sem_post(&update_display_sem);
}

void setup_perf_panel()
{
	int size;
	if (!data)
		return;
	if (perf_panel_window) {
		del_panel(perf_panel);
		delwin(perf_panel_window);
	}
	size = g_hash_table_size(data->perf_list);
	perf_panel_window = create_window(size + 2, 30, 10, 10);
	perf_panel = new_panel(perf_panel_window);
	perf_panel_visible = 0;
	hide_panel(perf_panel);
}

void update_perf_panel(int line_selected, int toggle_view, int toggle_sort)
{
	int i;
	struct perfcounter *perf;
	GList *perflist;

	if (!data)
		return;

	werase(perf_panel_window);
	box(perf_panel_window, 0 , 0);
	set_window_title(perf_panel_window, "Perf Preferences ");
	wattron(perf_panel_window, A_BOLD);
	mvwprintw(perf_panel_window, g_hash_table_size(data->perf_list) + 1, 1,
			" 's' to sort");
	wattroff(perf_panel_window, A_BOLD);

	if (toggle_sort == 1) {
		i = 0;
		perflist = g_list_first(g_hash_table_get_keys(data->perf_list));
		while (perflist) {
			perf = g_hash_table_lookup(data->perf_list, perflist->data);
			if (i != line_selected)
				perf->sort = 0;
			else
				perf->sort = 1;
			i++;
			perflist = g_list_next(perflist);
		}
		update_current_view();
	}

	i = 0;
	perflist = g_list_first(g_hash_table_get_keys(data->perf_list));
	while (perflist) {
		perf = g_hash_table_lookup(data->perf_list, perflist->data);
		if (i == line_selected && toggle_view == 1) {
			perf->visible = perf->visible == 1 ? 0:1;
			update_current_view();
		}
		if (i == line_selected) {
			wattron(perf_panel_window, COLOR_PAIR(5));
			mvwhline(perf_panel_window, i + 1, 1, ' ', 30 - 2);
		}
		if (perf->sort == 1)
			wattron(perf_panel_window, A_BOLD);
		mvwprintw(perf_panel_window, i + 1, 1, "[%c] %s",
				perf->visible == 1 ? 'x' : ' ',
				(char *) perflist->data + 6);
		wattroff(perf_panel_window, A_BOLD);
		wattroff(perf_panel_window, COLOR_PAIR(5));
		i++;
		perflist = g_list_next(perflist);
	}
	update_panels();
	doupdate();
}


void toggle_perf_panel(void)
{
	if (perf_panel_visible) {
		hide_panel(perf_panel);
		perf_panel_visible = 0;
	} else {
		setup_perf_panel();
		update_perf_panel(perf_line_selected, 0, 0);
		show_panel(perf_panel);
		perf_panel_visible = 1;
	}
	update_panels();
	doupdate();
}

void display(unsigned int index)
{
	last_display_index = index;
	currently_displayed_index = index;
	data = g_ptr_array_index(copies, index);
	if (!data)
		return;
	max_elements = data->process_table->len;
	update_current_view();
	update_footer();
	update_panels();
	doupdate();
}

void pause_display()
{
	toggle_pause = 1;
	print_log("Pause");
	sem_wait(&pause_sem);
}

void resume_display()
{
	toggle_pause = -1;
	print_log("Resume");
	sem_post(&pause_sem);
}

void *handle_keyboard(void *p)
{
	int ch;
	while((ch = getch())) {
		switch(ch) {
		/* Move the cursor and scroll */
		case KEY_DOWN:
			if (perf_panel_visible) {
				if (perf_line_selected < g_hash_table_size(data->perf_list) - 1)
					perf_line_selected++;
				update_perf_panel(perf_line_selected, 0, 0);
			} else {
				if (selected_line < (max_center_lines - 1) &&
						selected_line < max_elements - 1) {
					selected_line++;
					selected_in_list++;
				} else if (selected_in_list < (max_elements - 1)
						&& (list_offset < (max_elements - max_center_lines))) {
					selected_in_list++;
					list_offset++;
				}
				update_current_view();
			}
			break;
		case KEY_NPAGE:
			if ((selected_line + 10 < max_center_lines - 1) &&
					((selected_line + 10) < max_elements - 1)) {
				selected_line += 10;
				selected_in_list += 10;
			} else if (max_elements > max_center_lines) {
				selected_line = max_center_lines - 1;
				if (selected_in_list + 10 < max_elements - 1) {
					selected_in_list += 10;
					list_offset += (selected_in_list - max_center_lines + 1);
				}
			} else if (selected_line + 10 > max_elements) {
				selected_line = max_elements - 1;
			}
			update_current_view();
			break;
		case KEY_UP:
			if (perf_panel_visible) {
				if (perf_line_selected > 0)
					perf_line_selected--;
				update_perf_panel(perf_line_selected, 0, 0);
			} else {
				if (selected_line > 0) {
					selected_line--;
					selected_in_list--;
				} else if (selected_in_list > 0 && list_offset > 0) {
					selected_in_list--;
					list_offset--;
				}
				update_current_view();
			}
			break;
		case KEY_PPAGE:
			if (selected_line - 10 > 0)
				selected_line -= 10;
			else
				selected_line = 0;
			update_current_view();
			break;

		/* Navigate the history with arrows */
		case KEY_LEFT:
			if (currently_displayed_index > 0) {
				currently_displayed_index--;
				print_log("Going back in time");
			} else {
				print_log("Cannot rewind, last data is already displayed");
			}
			data = g_ptr_array_index(copies, currently_displayed_index);
			max_elements = data->process_table->len;

			/* we force to pause the display when moving in time */
			if (toggle_pause < 0)
				pause_display();

			update_current_view();
			update_footer();
			break;
		case KEY_RIGHT:
			if (currently_displayed_index < last_display_index) {
				currently_displayed_index++;
				print_log("Going forward in time");
				data = g_ptr_array_index(copies, currently_displayed_index);
				max_elements = data->process_table->len;
				update_current_view();
				update_footer();
			} else {
				print_log("Manually moving forward");
				sem_post(&timer);
				/* we force to resume the refresh when moving forward */
				if (toggle_pause > 0)
					resume_display();
			}

			break;
		case ' ':
			if (perf_panel_visible)
				update_perf_panel(perf_line_selected, 1, 0);
			break;
		case 's':
			if (perf_panel_visible)
				update_perf_panel(perf_line_selected, 0, 1);
			break;

		case 13: /* FIXME : KEY_ENTER ?? */
			if (current_view == cpu) {
				current_view = process_details;
			}
			update_current_view();
			break;

		case KEY_F(1):
			toggle_tree *= -1;
			current_view = cpu;
			update_current_view();
			break;
		case KEY_F(2):
			current_view = cpu;
			update_current_view();
			break;
		case KEY_F(3):
			current_view = perf;
			toggle_tree = -1;
			update_current_view();
			break;
		case KEY_F(4):
			current_view = fileio;
			toggle_tree = -1;
			update_current_view();
			break;
		case KEY_F(5):
			current_view = netio;
			toggle_tree = -1;
			update_current_view();
			break;
		case KEY_F(6):
			current_view = iostream;
			toggle_tree = -1;
			update_current_view();
			break;
		case KEY_F(10):
		case 'q':
			reset_ncurses();
			break;
		case 't':
			toggle_threads *= -1;
			update_current_view();
			break;
		case 'p':
			if (toggle_pause < 0) {
				pause_display();
			} else {
				resume_display();
			}
			break;
		case 'P':
			toggle_perf_panel();
			break;
		default:
			if (data)
				update_current_view();
			break;
		}
		update_footer();
	}
	return NULL;
}

void init_ncurses()
{
	sem_init(&update_display_sem, 0, 1);
	init_screen();

	header = create_window(7, COLS - 1, 0, 0);
	center = create_window(LINES - 7 - 7, COLS - 1, 7, 0);
	status = create_window(MAX_LOG_LINES + 2, COLS - 1, LINES - 7, 0);
	footer = create_window(1, COLS - 1, LINES - 1, 0);

	print_log("Starting display");

	main_panel = new_panel(center);
	setup_perf_panel();

	current_view = cpu;

	basic_header();
	update_footer();

	pthread_create(&keyboard_thread, NULL, handle_keyboard, (void *)NULL);
}


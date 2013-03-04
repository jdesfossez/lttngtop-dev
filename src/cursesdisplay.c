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
WINDOW *pref_panel_window = NULL;
PANEL *pref_panel, *main_panel;

int pref_panel_visible = 0;
int pref_line_selected = 0;
int pref_current_sort = 0;

int last_display_index, currently_displayed_index;

struct processtop *selected_process = NULL;
int selected_ret;

int selected_line = 0; /* select bar position */
int selected_in_list = 0; /* selection relative to the whole list */
int list_offset = 0; /* first index in the list to display (scroll) */
int nb_log_lines = 0;
char log_lines[MAX_LINE_LENGTH * MAX_LOG_LINES + MAX_LOG_LINES];

int max_elements = 80;

int toggle_threads = 1;
int toggle_virt = -1;
int toggle_pause = -1;

int filter_host_panel = 0;

int max_center_lines;

pthread_t keyboard_thread;

struct header_view cputopview[6];
struct header_view iostreamtopview[3];
struct header_view fileview[3];
struct header_view kprobeview[2];

void reset_ncurses()
{
	curs_set(1);
	endwin();
	quit = 1;
	sem_post(&pause_sem);
	sem_post(&timer);
	sem_post(&goodtodisplay);
	sem_post(&end_trace_sem);
	sem_post(&goodtoupdate);
}

static void handle_sigterm(int signal)
{
	pthread_cancel(keyboard_thread);
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
		init_pair(5, COLOR_BLACK, COLOR_YELLOW); /* select line */
		init_pair(6, COLOR_GREEN, COLOR_BLACK); /* selected process */
		init_pair(7, COLOR_RED, COLOR_YELLOW); /* selected process + line*/
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
	signal(SIGINT, handle_sigterm);
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
	mvwprintw(header, line, 16, "%d", value);
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

int process_selected(struct processtop *process)
{
	if (lookup_filter_tid_list(process->tid))
		return 1;
	return 0;
}

void update_selected_processes()
{
	if (process_selected(selected_process)) {
		remove_filter_tid_list(selected_process->tid);
	} else {
		add_filter_tid_list(selected_process);
	}
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
	print_key(footer, "F4", "IOTop  ", current_view == iostream);
	print_key(footer, "Enter", "Details  ", current_view == process_details);
	print_key(footer, "Space", "Highlight  ", 0);
	print_key(footer, "q", "Quit ", 0);
	print_key(footer, "r", "Pref  ", 0);
	print_key(footer, "t", "Threads  ", toggle_threads);
	print_key(footer, "v", "Virt  ", toggle_virt);
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
	mvwprintw(header, 2, 4, "Threads");
	mvwprintw(header, 3, 4, "FDs");
	wattroff(header, A_BOLD);
	wrefresh(header);
}

static void scale_unit(uint64_t bytes, char *ret)
{
	if (bytes >= 1000000000)
		sprintf(ret, "%" PRIu64 "G", bytes/1000000000);
	if (bytes >= 1000000)
		sprintf(ret, "%" PRIu64 "M", bytes/1000000);
	else if (bytes >= 1000)
		sprintf(ret, "%" PRIu64 "K", bytes/1000);
	else
		sprintf(ret, "%" PRIu64, bytes);
}

uint64_t total_io()
{
	int i;
	struct processtop *tmp;
	uint64_t total = 0;

	for (i = 0; i < data->process_table->len; i++) {
		tmp = g_ptr_array_index(data->process_table, i);
		total += tmp->fileread;
		total += tmp->filewrite;
	}

	return total;
}

void update_header()
{
	struct tm start, end;
	uint64_t ts_nsec_start, ts_nsec_end;
	char io[4];

	ts_nsec_start = data->start % NSEC_PER_SEC;
	start = format_timestamp(data->start);

	ts_nsec_end = data->end % NSEC_PER_SEC;
	end = format_timestamp(data->end);

	werase(header);
	box(header, 0 , 0);
	set_window_title(header, "Statistics for interval ");
	wattron(header, A_BOLD);

	wprintw(header, "[%02d:%02d:%02d.%09" PRIu64 ", %02d:%02d:%02d.%09" PRIu64 "[",
		start.tm_hour, start.tm_min, start.tm_sec, ts_nsec_start,
		end.tm_hour, end.tm_min, end.tm_sec, ts_nsec_end);
	mvwprintw(header, 1, 4, "CPUs");
	wattroff(header, A_BOLD);
	wprintw(header, "\t%d\t(max/cpu : %0.2f%)", data->cpu_table->len,
			100.0/data->cpu_table->len);
	print_headers(2, "Threads", data->nbthreads, data->nbnewthreads,
			-1*(data->nbdeadthreads));
	print_headers(3, "FDs", data->nbfiles, data->nbnewfiles,
			-1*(data->nbclosedfiles));
	scale_unit(total_io(), io);
	mvwprintw(header, 3, 43, "%sB/sec", io);
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

gint sort_by_tid_desc(gconstpointer p1, gconstpointer p2)
{
	struct processtop *n1 = *(struct processtop **)p1;
	struct processtop *n2 = *(struct processtop **)p2;
	unsigned long totaln1 = n1->tid;
	unsigned long totaln2 = n2->tid;

	if (totaln1 < totaln2)
		return 1;
	if (totaln1 == totaln2)
		return 0;
	return -1;
}

gint sort_by_pid_desc(gconstpointer p1, gconstpointer p2)
{
	struct processtop *n1 = *(struct processtop **)p1;
	struct processtop *n2 = *(struct processtop **)p2;
	unsigned long totaln1 = n1->pid;
	unsigned long totaln2 = n2->pid;

	if (totaln1 < totaln2)
		return 1;
	if (totaln1 == totaln2)
		return 0;
	return -1;
}

gint sort_by_process_read_desc(gconstpointer p1, gconstpointer p2)
{
	struct processtop *n1 = *(struct processtop **)p1;
	struct processtop *n2 = *(struct processtop **)p2;
	unsigned long totaln1 = n1->fileread;
	unsigned long totaln2 = n2->fileread;

	if (totaln1 < totaln2)
		return 1;
	if (totaln1 == totaln2)
		return 0;
	return -1;
}

gint sort_by_process_write_desc(gconstpointer p1, gconstpointer p2)
{
	struct processtop *n1 = *(struct processtop **)p1;
	struct processtop *n2 = *(struct processtop **)p2;
	unsigned long totaln1 = n1->filewrite;
	unsigned long totaln2 = n2->filewrite;

	if (totaln1 < totaln2)
		return 1;
	if (totaln1 == totaln2)
		return 0;
	return -1;
}

gint sort_by_process_total_desc(gconstpointer p1, gconstpointer p2)
{
	struct processtop *n1 = *(struct processtop **)p1;
	struct processtop *n2 = *(struct processtop **)p2;
	unsigned long totaln1 = n1->totalfilewrite + n1->totalfileread;
	unsigned long totaln2 = n2->totalfilewrite + n2->totalfileread;

	if (totaln1 < totaln2)
		return 1;
	if (totaln1 == totaln2)
		return 0;
	return -1;
}

gint sort_by_file_read_desc(gconstpointer p1, gconstpointer p2)
{
	struct files *n1 = *(struct files **)p1;
	struct files *n2 = *(struct files **)p2;
	unsigned long totaln1;
	unsigned long totaln2;

	totaln1 = n1->read;
	totaln2 = n2->read;

	if (totaln1 < totaln2)
		return 1;
	if (totaln1 == totaln2)
		return 0;
	return -1;
}

gint sort_by_file_write_desc(gconstpointer p1, gconstpointer p2)
{
	struct files *n1 = *(struct files **)p1;
	struct files *n2 = *(struct files **)p2;
	unsigned long totaln1;
	unsigned long totaln2;

	totaln1 = n1->write;
	totaln2 = n2->write;

	if (totaln1 < totaln2)
		return 1;
	if (totaln1 == totaln2)
		return 0;
	return -1;
}

gint sort_by_file_fd_desc(gconstpointer p1, gconstpointer p2)
{
	struct files *n1 = *(struct files **)p1;
	struct files *n2 = *(struct files **)p2;
	unsigned long totaln1;
	unsigned long totaln2;

	totaln1 = n1->fd;
	totaln2 = n2->fd;

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

void update_kprobes_display()
{
	int i, column;
	struct kprobes *probe;
	int header_offset = 2;
	int current_line = 0;

	set_window_title(center, "Kprobes Top ");
	wattron(center, A_BOLD);
	column = 1;
	for (i = 0; i < 2; i++) {
		if (kprobeview[i].sort) {
			wattron(center, A_UNDERLINE);
			pref_current_sort = i;
		}
		mvwprintw(center, 1, column, "%s", kprobeview[i].title);
		wattroff(center, A_UNDERLINE);
		column += 30;
	}
	wattroff(center, A_BOLD);

	for (i = 0; i < data->kprobes_table->len; i++) {
		column = 1;
		probe = g_ptr_array_index(data->kprobes_table, i);
		mvwprintw(center, current_line + header_offset, column,
				"%s", probe->probe_name + 6);
		column += 30;
		mvwprintw(center, current_line + header_offset, column,
				"%d", probe->count);
		current_line++;
	}
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
	int current_row_offset;
	int column;

	elapsed = data->end - data->start;
	maxcputime = elapsed * data->cpu_table->len / 100.0;

	if (cputopview[0].sort == 1)
		g_ptr_array_sort(data->process_table, sort_by_cpu_desc);
	else if (cputopview[1].sort == 1)
		g_ptr_array_sort(data->process_table, sort_by_pid_desc);
	else if (cputopview[2].sort == 1)
		g_ptr_array_sort(data->process_table, sort_by_tid_desc);
	else if (cputopview[3].sort == 1)
		g_ptr_array_sort(data->process_table, sort_by_cpu_desc);
	else
		g_ptr_array_sort(data->process_table, sort_by_cpu_desc);

	set_window_title(center, "CPU Top");
	wattron(center, A_BOLD);
	column = 1;
	for (i = 0; i < 6; i++) {
		if (toggle_virt < 0 && (i == 3 || i == 4)) {
			continue;
		}
		if (cputopview[i].sort) {
			wattron(center, A_UNDERLINE);
			pref_current_sort = i;
		}
		mvwprintw(center, 1, column, cputopview[i].title);
		wattroff(center, A_UNDERLINE);
		column += 10;
	}
	wattroff(center, A_BOLD);

	max_center_lines = LINES - 5 - 7 - 1 - header_offset;

	/* iterate the process (thread) list */
	for (i = list_offset; i < data->process_table->len &&
			nblinedisplayed < max_center_lines; i++) {
		tmp = g_ptr_array_index(data->process_table, i);
		current_row_offset = 1;
		if (toggle_filter > 0 && !lookup_filter_tid_list(tmp->tid))
			continue;

		if (tmp->pid != tmp->tid)
			if (toggle_threads == -1)
				continue;

		/* line */
		if (current_line == selected_line) {
			selected_process = tmp;
			wattron(center, COLOR_PAIR(5));
			mvwhline(center, current_line + header_offset, 1, ' ', COLS-3);
		}
		/* filtered process */
		if (process_selected(tmp)) {
			if (current_line == selected_line)
				wattron(center, COLOR_PAIR(7));
			else
				wattron(center, COLOR_PAIR(6));
		}
		/* CPU(%) */
		mvwprintw(center, current_line + header_offset,
				current_row_offset, "%1.2f",
				tmp->totalcpunsec / maxcputime);
		current_row_offset += 10;
		/* PID */
		mvwprintw(center, current_line + header_offset,
				current_row_offset, "%d", tmp->pid);
		current_row_offset += 10;
		/* TID */
		mvwprintw(center, current_line + header_offset,
				current_row_offset, "%d", tmp->tid);
		current_row_offset += 10;
		if (toggle_virt > 0) {
			/* VPID */
			mvwprintw(center, current_line + header_offset,
					current_row_offset, "%d", tmp->vpid);
			current_row_offset += 10;
			/* VTID */
			mvwprintw(center, current_line + header_offset,
					current_row_offset, "%d", tmp->vtid);
			current_row_offset += 10;
		}
		/* NAME */
		mvwprintw(center, current_line + header_offset,
				current_row_offset, "%s", tmp->comm);
		wattroff(center, COLOR_PAIR(7));
		wattroff(center, COLOR_PAIR(6));
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
	mvwprintw(center, line, 1, "%s", key);
	mvwprintw(center, line, 30, " ");
	wattroff(center, A_BOLD);
}

void update_process_details()
{
	unsigned long elapsed;
	double maxcputime;
	struct processtop *tmp;
	struct files *file_tmp;
	int i, j = 0;
	char unit[4];
	char filename_buf[COLS];
	int line = 1;
	int column;
	GPtrArray *newfilearray = g_ptr_array_new();
	GHashTableIter iter;
	struct perfcounter *perfn1, *perfn2;
	gpointer key;

	set_window_title(center, "Process details");


	tmp = find_process_tid(data,
			selected_process->tid,
			selected_process->comm);
	elapsed = data->end - data->start;
	maxcputime = elapsed * data->cpu_table->len / 100.0;

	print_key_title("Name", line++);
	wprintw(center, "%s", selected_process->comm);
	print_key_title("TID", line++);
	wprintw(center, "%d", selected_process->tid);
	if (!tmp) {
		print_key_title("Does not exit at this time", 3);
		return;
	}

	print_key_title("PID", line++);
	wprintw(center, "%d", tmp->pid);
	print_key_title("PPID", line++);
	wprintw(center, "%d", tmp->ppid);
	print_key_title("VPID", line++);
	wprintw(center, "%d", tmp->vpid);
	print_key_title("VTID", line++);
	wprintw(center, "%d", tmp->vtid);
	print_key_title("VPPID", line++);
	wprintw(center, "%d", tmp->vppid);
	print_key_title("CPU", line++);
	wprintw(center, "%1.2f %%", tmp->totalcpunsec/maxcputime);

	print_key_title("READ B/s", line++);
	scale_unit(tmp->fileread, unit);
	wprintw(center, "%s", unit);

	print_key_title("WRITE B/s", line++);
	scale_unit(tmp->filewrite, unit);
	wprintw(center, "%s", unit);

	g_hash_table_iter_init(&iter, global_perf_liszt);
	while (g_hash_table_iter_next (&iter, &key, (gpointer) &perfn1)) {
		print_key_title((char *) key, line++);
		perfn2 = g_hash_table_lookup(tmp->perf, (char *) key);
		wprintw(center, "%d", perfn2 ? perfn2->count : 0);
	}
	line++;

	wattron(center, A_BOLD);
	column = 1;
	for (i = 0; i < 3; i++) {
		if (fileview[i].sort) {
			pref_current_sort = i;
			wattron(center, A_UNDERLINE);
		}
		mvwprintw(center, line, column, fileview[i].title);
		wattroff(center, A_UNDERLINE);
		column += 10;
	}
	mvwprintw(center, line++, column, "FILENAME");
	wattroff(center, A_BOLD);

	/*
	 * since the process_files_table array could contain NULL file structures,
	 * and that the positions inside the array is important (it is the FD), we
	 * need to create a temporary array that we can sort.
	 */
	for (i = 0; i < tmp->process_files_table->len; i++) {
		file_tmp = g_ptr_array_index(tmp->process_files_table, i);
		if (file_tmp)
			g_ptr_array_add(newfilearray, file_tmp);
	}

	if (fileview[0].sort == 1)
		g_ptr_array_sort(newfilearray, sort_by_file_fd_desc);
	else if (fileview[1].sort == 1)
		g_ptr_array_sort(newfilearray, sort_by_file_read_desc);
	else if (fileview[2].sort == 1)
		g_ptr_array_sort(newfilearray, sort_by_file_write_desc);
	else
		g_ptr_array_sort(newfilearray, sort_by_file_read_desc);

	for (i = selected_line; i < newfilearray->len &&
			i < (selected_line + max_center_lines - line + 2); i++) {
		file_tmp = g_ptr_array_index(newfilearray, i);
		if (!file_tmp)
			continue;
		mvwprintw(center, line + j, 1, "%d", file_tmp->fd);
		scale_unit(file_tmp->read, unit);
		mvwprintw(center, line + j, 11, "%s", unit);
		scale_unit(file_tmp->write, unit);
		mvwprintw(center, line + j, 21, "%s", unit);
		snprintf(filename_buf, COLS - 25, "%s", file_tmp->name);
		mvwprintw(center, line + j, 31, "%s", filename_buf);
		j++;
	}
	g_ptr_array_free(newfilearray, TRUE);
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
	g_hash_table_iter_init(&iter, global_perf_liszt);
	while (g_hash_table_iter_next (&iter, &key, (gpointer) &perfn1)) {
		if (perfn1->visible) {
			if (perfn1->sort) {
				/* pref_current_sort = i; */
				wattron(center, A_UNDERLINE);
			}
			/* + 5 to strip the "perf_" prefix */
			mvwprintw(center, 1, perf_row, "%s",
					(char *) key + 5);
			wattroff(center, A_UNDERLINE);
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

		if (toggle_filter > 0 && !lookup_filter_tid_list(tmp->tid))
			continue;

		if (tmp->pid != tmp->tid)
			if (toggle_threads == -1)
				continue;

		if (process_selected(tmp)) {
			if (current_line == selected_line)
				wattron(center, COLOR_PAIR(7));
			else
				wattron(center, COLOR_PAIR(6));
		}
		if (current_line == selected_line) {
			selected_process = tmp;
			wattron(center, COLOR_PAIR(5));
			mvwhline(center, current_line + header_offset, 1, ' ', COLS-3);
		}

		mvwprintw(center, current_line + header_offset, 1, "%d", tmp->pid);
		mvwprintw(center, current_line + header_offset, 11, "%d", tmp->tid);
		mvwprintw(center, current_line + header_offset, 22, "%s", tmp->comm);

		g_hash_table_iter_init(&iter, global_perf_liszt);

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

		wattroff(center, COLOR_PAIR(6));
		wattroff(center, COLOR_PAIR(5));
		nblinedisplayed++;
		current_line++;
	}
}

void update_iostream()
{
	int i;
	int header_offset = 2;
	struct processtop *tmp;
	int nblinedisplayed = 0;
	int current_line = 0;
	int total = 0;
	char unit[4];
	int column;

	set_window_title(center, "IO Top");
	wattron(center, A_BOLD);
	mvwprintw(center, 1, 1, "PID");
	mvwprintw(center, 1, 11, "TID");
	mvwprintw(center, 1, 22, "NAME");
	column = 40;
	for (i = 0; i < 3; i++) {
		if (iostreamtopview[i].sort) {
			pref_current_sort = i;
			wattron(center, A_UNDERLINE);
		}
		mvwprintw(center, 1, column, iostreamtopview[i].title);
		wattroff(center, A_UNDERLINE);
		column += 12;
	}
	wattroff(center, A_BOLD);
	wattroff(center, A_UNDERLINE);

	if (iostreamtopview[0].sort == 1)
		g_ptr_array_sort(data->process_table, sort_by_process_read_desc);
	else if (iostreamtopview[1].sort == 1)
		g_ptr_array_sort(data->process_table, sort_by_process_write_desc);
	else if (iostreamtopview[2].sort == 1)
		g_ptr_array_sort(data->process_table, sort_by_process_total_desc);
	else
		g_ptr_array_sort(data->process_table, sort_by_process_total_desc);

	for (i = list_offset; i < data->process_table->len &&
			nblinedisplayed < max_center_lines; i++) {
		tmp = g_ptr_array_index(data->process_table, i);

		if (toggle_filter > 0 && !lookup_filter_tid_list(tmp->tid))
			continue;

		if (tmp->pid != tmp->tid)
			if (toggle_threads == -1)
				continue;

		if (process_selected(tmp)) {
			if (current_line == selected_line)
				wattron(center, COLOR_PAIR(7));
			else
				wattron(center, COLOR_PAIR(6));
		}
		if (current_line == selected_line) {
			selected_process = tmp;
			wattron(center, COLOR_PAIR(5));
			mvwhline(center, current_line + header_offset, 1, ' ', COLS-3);
		}
		/* TGID */
		mvwprintw(center, current_line + header_offset, 1, "%d", tmp->pid);
		/* PID */
		mvwprintw(center, current_line + header_offset, 11, "%d", tmp->tid);
		/* NAME */
		mvwprintw(center, current_line + header_offset, 22, "%s", tmp->comm);

		/* READ (bytes/sec) */
		scale_unit(tmp->fileread, unit);
		mvwprintw(center, current_line + header_offset, 40, "%s", unit);

		/* WRITE (bytes/sec) */
		scale_unit(tmp->filewrite, unit);
		mvwprintw(center, current_line + header_offset, 52, "%s", unit);

		/* TOTAL STREAM */
		total = tmp->totalfileread + tmp->totalfilewrite;

		scale_unit(total, unit);
		mvwprintw(center, current_line + header_offset, 64, "%s", unit);

		wattroff(center, COLOR_PAIR(6));
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
	case iostream:
		update_iostream();
		break;
	case tree:
		update_cputop_display();
		break;
	case kprobes:
		update_kprobes_display();
		break;
	default:
		break;
	}
	update_panels();
	doupdate();
	sem_post(&update_display_sem);
}

void update_process_detail_sort(int *line_selected)
{
	int i;
	int size;

	size = 3;

	if (*line_selected > (size - 1))
		*line_selected = size - 1;
	else if (*line_selected < 0)
		*line_selected = 0;

	if (fileview[*line_selected].sort == 1)
		fileview[*line_selected].reverse = 1;
	for (i = 0; i < size; i++)
		fileview[i].sort = 0;
	fileview[*line_selected].sort = 1;
}

void update_process_detail_pref(int *line_selected, int toggle_view, int toggle_sort)
{
	int i;
	int size;

	if (!data)
		return;
	if (pref_panel_window) {
		del_panel(pref_panel);
		delwin(pref_panel_window);
	}
	size = 3;

	pref_panel_window = create_window(size + 2, 30, 10, 10);
	pref_panel = new_panel(pref_panel_window);

	werase(pref_panel_window);
	box(pref_panel_window, 0 , 0);
	set_window_title(pref_panel_window, "Process Detail Preferences ");
	wattron(pref_panel_window, A_BOLD);
	mvwprintw(pref_panel_window, size + 1, 1,
			" 's' : sort, space : toggle");
	wattroff(pref_panel_window, A_BOLD);

	if (*line_selected > (size - 1))
		*line_selected = size - 1;
	else if (*line_selected < 0)
		*line_selected = 0;
	if (toggle_sort == 1) {
		update_process_detail_sort(line_selected);
		update_current_view();
	}

	for (i = 0; i < size; i++) {
		if (i == *line_selected) {
			wattron(pref_panel_window, COLOR_PAIR(5));
			mvwhline(pref_panel_window, i + 1, 1, ' ', 30 - 2);
		}
		if (fileview[i].sort == 1)
			wattron(pref_panel_window, A_BOLD);
		mvwprintw(pref_panel_window, i + 1, 1, "[-] %s",
				fileview[i].title);
		wattroff(pref_panel_window, A_BOLD);
		wattroff(pref_panel_window, COLOR_PAIR(5));

	}
	update_panels();
	doupdate();
}

void update_iostream_sort(int *line_selected)
{
	int i;
	int size;

	size = 3;
	if (*line_selected > (size - 1))
		*line_selected = size - 1;
	else if (*line_selected < 0)
		*line_selected = 0;
	if (iostreamtopview[*line_selected].sort == 1)
		iostreamtopview[*line_selected].reverse = 1;
	for (i = 0; i < size; i++)
		iostreamtopview[i].sort = 0;
	iostreamtopview[*line_selected].sort = 1;

}

void update_iostream_pref(int *line_selected, int toggle_view, int toggle_sort)
{
	int i;
	int size;

	if (!data)
		return;
	if (pref_panel_window) {
		del_panel(pref_panel);
		delwin(pref_panel_window);
	}
	size = 3;

	pref_panel_window = create_window(size + 2, 30, 10, 10);
	pref_panel = new_panel(pref_panel_window);

	werase(pref_panel_window);
	box(pref_panel_window, 0 , 0);
	set_window_title(pref_panel_window, "IOTop Preferences ");
	wattron(pref_panel_window, A_BOLD);
	mvwprintw(pref_panel_window, size + 1, 1,
			" 's' : sort, space : toggle");
	wattroff(pref_panel_window, A_BOLD);

	if (*line_selected > (size - 1))
		*line_selected = size - 1;
	else if (*line_selected < 0)
		*line_selected = 0;
	if (toggle_sort == 1) {
		update_iostream_sort(line_selected);
		update_current_view();
	}

	for (i = 0; i < size; i++) {
		if (i == *line_selected) {
			wattron(pref_panel_window, COLOR_PAIR(5));
			mvwhline(pref_panel_window, i + 1, 1, ' ', 30 - 2);
		}
		if (iostreamtopview[i].sort == 1)
			wattron(pref_panel_window, A_BOLD);
		mvwprintw(pref_panel_window, i + 1, 1, "[-] %s",
				iostreamtopview[i].title);
		wattroff(pref_panel_window, A_BOLD);
		wattroff(pref_panel_window, COLOR_PAIR(5));

	}
	update_panels();
	doupdate();
}

void update_cpu_sort(int *line_selected)
{
	int i;
	int size = 3;

	if (*line_selected > (size - 1))
		*line_selected = size - 1;
	else if (*line_selected < 0)
		*line_selected = 0;

	/* special case, we don't support sorting by procname for now */
	if (*line_selected != 3) {
		if (cputopview[*line_selected].sort == 1)
			cputopview[*line_selected].reverse = 1;
		for (i = 0; i < size; i++)
			cputopview[i].sort = 0;
		cputopview[*line_selected].sort = 1;
	}
}

void update_cpu_pref(int *line_selected, int toggle_view, int toggle_sort)
{
	int i;
	int size;

	if (!data)
		return;
	if (pref_panel_window) {
		del_panel(pref_panel);
		delwin(pref_panel_window);
	}
	size = 4;

	pref_panel_window = create_window(size + 2, 30, 10, 10);
	pref_panel = new_panel(pref_panel_window);

	werase(pref_panel_window);
	box(pref_panel_window, 0 , 0);
	set_window_title(pref_panel_window, "CPUTop Preferences ");
	wattron(pref_panel_window, A_BOLD);
	mvwprintw(pref_panel_window, size + 1, 1,
			" 's' : sort, space : toggle");
	wattroff(pref_panel_window, A_BOLD);

	if (*line_selected > (size - 1))
		*line_selected = size - 1;
	else if (*line_selected < 0)
		*line_selected = 0;
	if (toggle_sort == 1) {
		update_cpu_sort(line_selected);
		update_current_view();
	}

	for (i = 0; i < size; i++) {
		if (i == *line_selected) {
			wattron(pref_panel_window, COLOR_PAIR(5));
			mvwhline(pref_panel_window, i + 1, 1, ' ', 30 - 2);
		}
		if (cputopview[i].sort == 1)
			wattron(pref_panel_window, A_BOLD);
		mvwprintw(pref_panel_window, i + 1, 1, "[-] %s",
				cputopview[i].title);
		wattroff(pref_panel_window, A_BOLD);
		wattroff(pref_panel_window, COLOR_PAIR(5));

	}
	update_panels();
	doupdate();
}

void update_perf_sort(int *line_selected)
{
	int i;
	struct perfcounter *perf;
	GList *perflist;
	int size;

	size = g_hash_table_size(global_perf_liszt);
	if (*line_selected > (size - 1))
		*line_selected = size - 1;
	else if (*line_selected < 0)
		*line_selected = 0;

	i = 0;
	perflist = g_list_first(g_hash_table_get_keys(global_perf_liszt));
	while (perflist) {
		perf = g_hash_table_lookup(global_perf_liszt, perflist->data);
		if (i != *line_selected)
			perf->sort = 0;
		else
			perf->sort = 1;
		i++;
		perflist = g_list_next(perflist);
	}
}

void update_perf_pref(int *line_selected, int toggle_view, int toggle_sort)
{
	int i;
	struct perfcounter *perf;
	GList *perflist;
	int size;

	if (!data)
		return;
	if (pref_panel_window) {
		del_panel(pref_panel);
		delwin(pref_panel_window);
	}
	size = g_hash_table_size(global_perf_liszt);

	pref_panel_window = create_window(size + 2, 30, 10, 10);
	pref_panel = new_panel(pref_panel_window);

	werase(pref_panel_window);
	box(pref_panel_window, 0 , 0);
	set_window_title(pref_panel_window, "Perf Preferences ");
	wattron(pref_panel_window, A_BOLD);
	mvwprintw(pref_panel_window, g_hash_table_size(global_perf_liszt) + 1, 1,
			" 's' : sort, space : toggle");
	wattroff(pref_panel_window, A_BOLD);

	if (*line_selected > (size - 1))
		*line_selected = size - 1;
	else if (*line_selected < 0)
		*line_selected = 0;

	if (toggle_sort == 1) {
		update_perf_sort(line_selected);
		update_current_view();
	}

	i = 0;
	perflist = g_list_first(g_hash_table_get_keys(global_perf_liszt));
	while (perflist) {
		perf = g_hash_table_lookup(global_perf_liszt, perflist->data);
		if (i == *line_selected && toggle_view == 1) {
			perf->visible = perf->visible == 1 ? 0:1;
			update_current_view();
		}
		if (i == *line_selected) {
			wattron(pref_panel_window, COLOR_PAIR(5));
			mvwhline(pref_panel_window, i + 1, 1, ' ', 30 - 2);
		}
		if (perf->sort == 1)
			wattron(pref_panel_window, A_BOLD);
		mvwprintw(pref_panel_window, i + 1, 1, "[%c] %s",
				perf->visible == 1 ? 'x' : ' ',
				(char *) perflist->data + 5);
		wattroff(pref_panel_window, A_BOLD);
		wattroff(pref_panel_window, COLOR_PAIR(5));
		i++;
		perflist = g_list_next(perflist);
	}
	update_panels();
	doupdate();
}

void update_hostname_pref(int *line_selected, int toggle_filter, int toggle_sort)
{
	int i;
	struct host *host;
	GList *hostlist;
	int size;

	if (!data)
		return;
	if (pref_panel_window) {
		del_panel(pref_panel);
		delwin(pref_panel_window);
	}
	size = g_hash_table_size(global_host_list);

	pref_panel_window = create_window(size + 2, 30, 10, 10);
	pref_panel = new_panel(pref_panel_window);

	werase(pref_panel_window);
	box(pref_panel_window, 0 , 0);
	set_window_title(pref_panel_window, "Hosts Preferences ");
	wattron(pref_panel_window, A_BOLD);
	mvwprintw(pref_panel_window, g_hash_table_size(global_host_list) + 1, 1,
			" space : toggle filter");
	wattroff(pref_panel_window, A_BOLD);

	if (*line_selected > (size - 1))
		*line_selected = size - 1;
	else if (*line_selected < 0)
		*line_selected = 0;

	i = 0;
	hostlist = g_list_first(g_hash_table_get_keys(global_host_list));
	while (hostlist) {
		host = g_hash_table_lookup(global_host_list, hostlist->data);
		if (i == *line_selected && toggle_filter == 1) {
			host->filter = host->filter == 1 ? 0:1;
			update_hostname_filter(host);
			update_current_view();
		}
		if (i == *line_selected) {
			wattron(pref_panel_window, COLOR_PAIR(5));
			mvwhline(pref_panel_window, i + 1, 1, ' ', 30 - 2);
		}
		if (host->filter == 1)
			wattron(pref_panel_window, A_BOLD);
		mvwprintw(pref_panel_window, i + 1, 1, "[%c] %s",
				host->filter == 1 ? 'x' : ' ',
				(char *) hostlist->data);
		wattroff(pref_panel_window, A_BOLD);
		wattroff(pref_panel_window, COLOR_PAIR(5));
		i++;
		hostlist = g_list_next(hostlist);
	}
	update_panels();
	doupdate();
}

int update_preference_panel(int *line_selected, int toggle_view, int toggle_sort)
{
	int ret = 0;

	switch(current_view) {
		case perf:
			if (filter_host_panel)
				update_hostname_pref(line_selected,
						toggle_view, toggle_sort);
			else
				update_perf_pref(line_selected,
						toggle_view, toggle_sort);
			break;
		case cpu:
			if (filter_host_panel)
				update_hostname_pref(line_selected,
						toggle_view, toggle_sort);
			else
				update_cpu_pref(line_selected,
						toggle_view, toggle_sort);
			break;
		case iostream:
			if (filter_host_panel)
				update_hostname_pref(line_selected,
						toggle_view, toggle_sort);
			else
				update_iostream_pref(line_selected,
						toggle_view, toggle_sort);
			break;
		case process_details:
			update_process_detail_pref(line_selected,
					toggle_view, toggle_sort);
			break;
		default:
			ret = -1;
			break;
	}

	return ret;
}

int update_sort(int *line_selected)
{
	int ret = 0;

	switch(current_view) {
		case perf:
			update_perf_sort(line_selected);
			break;
		case cpu:
			update_cpu_sort(line_selected);
			break;
		case iostream:
			update_iostream_sort(line_selected);
			break;
		case process_details:
			update_process_detail_sort(line_selected);
			break;
		default:
			ret = -1;
			break;
	}

	return ret;
}

void toggle_pref_panel(void)
{
	int ret;

	if (pref_panel_visible) {
		hide_panel(pref_panel);
		pref_panel_visible = 0;
	} else {
		ret = update_preference_panel(&pref_line_selected, 0, 0);
		if (ret < 0)
			return;
		show_panel(pref_panel);
		pref_panel_visible = 1;
	}
	update_panels();
	doupdate();
}

void toggle_host_panel(void)
{
	int ret;

	filter_host_panel = filter_host_panel ? 0 : 1;
	if (pref_panel_visible) {
		hide_panel(pref_panel);
		pref_panel_visible = 0;
	} else {
		ret = update_preference_panel(&pref_line_selected, 0, 0);
		if (ret < 0)
			return;
		show_panel(pref_panel);
		pref_panel_visible = 1;
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
		case 'j':
		case KEY_DOWN:
			if (pref_panel_visible) {
				pref_line_selected++;
				update_preference_panel(&pref_line_selected, 0, 0);
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
			break;
		case 'k':
		case KEY_UP:
			if (pref_panel_visible) {
				if (pref_line_selected > 0)
					pref_line_selected--;
				update_preference_panel(&pref_line_selected, 0, 0);
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
				if (toggle_pause > 0) {
					sem_post(&pause_sem);
					update_current_view();
					sem_wait(&pause_sem);
				}
			}

			break;
		case ' ':
			if (pref_panel_visible) {
				update_preference_panel(&pref_line_selected, 1, 0);
			} else {
				update_selected_processes();
				if (toggle_filter > 0) {
					max_elements = g_hash_table_size(global_filter_list);
					if (selected_line >= max_elements)
						selected_line = max_elements - 1;
				}
				update_current_view();
			}
			break;
		case 's':
			if (pref_panel_visible)
				update_preference_panel(&pref_line_selected, 0, 1);
			break;
		case '>':
			/* perf uses a hashtable, it is ordered backward */
			if (current_view == perf) {
				pref_current_sort--;
			} else if (!pref_panel_visible) {
				pref_current_sort++;
			}
			update_sort(&pref_current_sort);
			update_current_view();
			break;
		case '<':
			/* perf uses a hashtable, it is ordered backward */
			if (current_view == perf) {
				pref_current_sort++;
			} else if (!pref_panel_visible) {
				pref_current_sort--;
			}
			update_sort(&pref_current_sort);
			update_current_view();
			break;

		case 13: /* FIXME : KEY_ENTER ?? */
			if (pref_panel_visible)
				break;
			if (current_view != process_details) {
				previous_view = current_view;
				current_view = process_details;
			} else {
				current_view = previous_view;
				previous_view = process_details;
			}
			selected_line = 0;
			update_current_view();
			break;

		case KEY_F(1):
			if (pref_panel_visible)
				toggle_pref_panel();
			current_view = cpu;
			selected_line = 0;
			update_current_view();
			break;
		case KEY_F(2):
			if (pref_panel_visible)
				toggle_pref_panel();
			current_view = cpu;
			selected_line = 0;
			update_current_view();
			break;
		case KEY_F(3):
			if (pref_panel_visible)
				toggle_pref_panel();
			current_view = perf;
			selected_line = 0;
			update_current_view();
			break;
		case KEY_F(4):
			if (pref_panel_visible)
				toggle_pref_panel();
			current_view = iostream;
			selected_line = 0;
			update_current_view();
			break;
		case KEY_F(5):
			if (pref_panel_visible)
				toggle_pref_panel();
			current_view = kprobes;
			selected_line = 0;
			update_current_view();
			break;
		case KEY_F(10):
		case 'q':
			reset_ncurses();
			/* exit keyboard thread */
			pthread_exit(0);
			break;
		case 'f':
			toggle_filter *= -1;
			selected_line = 0;
			if (toggle_filter > 0)
				max_elements = g_hash_table_size(global_filter_list);
			else
				max_elements = data->process_table->len;
			update_current_view();
			break;
		case 'h':
			toggle_host_panel();
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
		case 'r':
			toggle_pref_panel();
			break;
		case 'v':
			toggle_virt *= -1;
			update_current_view();
			break;
		/* ESCAPE, but slow to process, don't know why */
		case 27:
			if (pref_panel_visible)
				toggle_pref_panel();
			else if (current_view == process_details) {
				current_view = previous_view;
				previous_view = process_details;
			}
			update_current_view();
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

void init_view_headers()
{
	cputopview[0].title = strdup("CPU(%)");
	cputopview[0].sort = 1;
	cputopview[1].title = strdup("PID");
	cputopview[2].title = strdup("TID");
	cputopview[3].title = strdup("VPID");
	cputopview[4].title = strdup("VTID");
	cputopview[5].title = strdup("NAME");

	iostreamtopview[0].title = strdup("R (B/sec)");
	iostreamtopview[1].title = strdup("W (B/sec)");
	iostreamtopview[2].title = strdup("Total (B)");
	iostreamtopview[2].sort = 1;

	fileview[0].title = strdup("FD");
	fileview[1].title = strdup("READ");
	fileview[1].sort = 1;
	fileview[2].title = strdup("WRITE");

	kprobeview[0].title = strdup("NAME");
	kprobeview[1].title = strdup("HIT");
	kprobeview[1].sort = 1;
}

void init_ncurses()
{
	sem_init(&update_display_sem, 0, 1);
	init_view_headers();
	init_screen();

	header = create_window(5, COLS - 1, 0, 0);
	center = create_window(LINES - 5 - 7, COLS - 1, 5, 0);
	status = create_window(MAX_LOG_LINES + 2, COLS - 1, LINES - 7, 0);
	footer = create_window(1, COLS - 1, LINES - 1, 0);

	print_log("Starting display");

	main_panel = new_panel(center);

	current_view = cpu;

	basic_header();
	update_footer();

	pthread_create(&keyboard_thread, NULL, handle_keyboard, (void *)NULL);
}

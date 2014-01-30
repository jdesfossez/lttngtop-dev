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

#include <lib/babeltrace/ctf/types.h>
#include <lib/babeltrace/ctf-ir/metadata.h>
#include <lib/babeltrace/clock-internal.h>
#include "ctf-index.h"

/* Copied from babeltrace/formats/ctf/events-private.h */
static inline
uint64_t ctf_get_real_timestamp(struct ctf_stream_definition *stream,
			uint64_t timestamp)
{
	uint64_t ts_nsec;
	struct ctf_trace *trace = stream->stream_class->trace;
	struct trace_collection *tc = trace->parent.collection;
	uint64_t tc_offset;

	if (tc->clock_use_offset_avg)
		tc_offset = tc->single_clock_offset_avg;
	else
		tc_offset = trace->parent.single_clock->offset;

	ts_nsec = clock_cycles_to_ns(stream->current_clock, timestamp);
	ts_nsec += tc_offset;	/* Add offset */
	return ts_nsec;
}

int list_sessions(void);
void dump_packet_index(struct ctf_packet_index *index);
int get_next_index(int id, struct packet_index *index);
void ctf_live_packet_seek(struct bt_stream_pos *stream_pos, size_t index,
		int whence);
int open_trace(struct bt_context **bt_ctx);
int setup_network_live(char *hostname, int begin);

#endif /* _LIVE_H */

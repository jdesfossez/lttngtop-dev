/*
 * Copyright (C) 2013 - Julien Desfossez <jdesfossez@efficios.com>
 *                      Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "lttng-viewer.h"
#include "ctf-index.h"
#include "network-live.h"

#include <babeltrace/babeltrace.h>
#include <babeltrace/ctf/events.h>
#include <babeltrace/ctf/callbacks.h>
#include <babeltrace/ctf/iterator.h>

/* for packet_index */
#include <babeltrace/ctf/types.h>

#include <babeltrace/ctf/metadata.h>
#include <babeltrace/ctf-text/types.h>
#include <babeltrace/ctf/events-internal.h>

/*
 * Memory allocation zeroed
 */
#define zmalloc(x) calloc(1, x)
/* FIXME : completely arbitrary */
#define mmap_size 524288

static int control_sock;
struct live_session *session;

struct viewer_stream {
	uint64_t id;
	uint64_t ctf_trace_id;
	void *mmap_base;
	int fd;
	int metadata_flag;
	int first_read;
	char path[PATH_MAX];
};

struct live_session {
	struct viewer_stream *streams;
	uint64_t live_timer_interval;
	uint64_t stream_count;
};

static
int connect_viewer(char *hostname)
{
	struct hostent *host;
	struct sockaddr_in server_addr;
	int ret;

	host = gethostbyname(hostname);
	if (!host) {
		ret = -1;
		goto end;
	}

	if ((control_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("Socket");
		ret = -1;
		goto end;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(5344);
	server_addr.sin_addr = *((struct in_addr *) host->h_addr);
	bzero(&(server_addr.sin_zero), 8);

	if (connect(control_sock, (struct sockaddr *) &server_addr,
				sizeof(struct sockaddr)) == -1) {
		perror("Connect");
		ret = -1;
		goto end;
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(5345);
	server_addr.sin_addr = *((struct in_addr *) host->h_addr);
	bzero(&(server_addr.sin_zero), 8);

	ret = 0;

end:
	return ret;
}

static
int establish_connection(void)
{
	struct lttng_viewer_cmd cmd;
	struct lttng_viewer_connect connect;
	int ret;

	cmd.cmd = htobe32(VIEWER_CONNECT);
	cmd.data_size = sizeof(connect);
	cmd.cmd_version = 0;

	connect.major = htobe32(2);
	connect.minor = htobe32(4);
	connect.type = htobe32(VIEWER_CLIENT_COMMAND);

	do {
		ret = send(control_sock, &cmd, sizeof(cmd), 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		fprintf(stderr, "Error sending cmd\n");
		goto error;
	}
	do {
		ret = send(control_sock, &connect, sizeof(connect), 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		fprintf(stderr, "Error sending version\n");
		goto error;
	}

	do {
		ret = recv(control_sock, &connect, sizeof(connect), 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		fprintf(stderr, "Error receiving version\n");
		goto error;
	}
	fprintf(stderr, "  - Received viewer session ID : %" PRIu64 "\n",
			be64toh(connect.viewer_session_id));
	fprintf(stderr, "  - Received version : %u.%u\n", be32toh(connect.major),
			be32toh(connect.minor));

	ret = 0;

error:
	return ret;
}

int list_sessions(void)
{
	struct lttng_viewer_cmd cmd;
	struct lttng_viewer_list_sessions list;
	struct lttng_viewer_session lsession;
	int i, ret;
	int first_session = 0;

	cmd.cmd = htobe32(VIEWER_LIST_SESSIONS);
	cmd.data_size = 0;
	cmd.cmd_version = 0;

	do {
		ret = send(control_sock, &cmd, sizeof(cmd), 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		fprintf(stderr, "Error sending cmd\n");
		goto error;
	}

	do {
		ret = recv(control_sock, &list, sizeof(list), 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		fprintf(stderr, "Error receiving session list\n");
		goto error;
	}

	fprintf(stderr, "  - %u active session(s)\n", be32toh(list.sessions_count));
	for (i = 0; i < be32toh(list.sessions_count); i++) {
		do {
			ret = recv(control_sock, &lsession, sizeof(lsession), 0);
		} while (ret < 0 && errno == EINTR);
		if (ret < 0) {
			fprintf(stderr, "Error receiving session\n");
			goto error;
		}
		fprintf(stderr, "    - %" PRIu64 " : %s on host %s (timer = %u, "
				"%u client(s) connected)\n",
				be64toh(lsession.id), lsession.session_name,
				lsession.hostname, be32toh(lsession.live_timer),
				be32toh(lsession.clients));
		if (first_session <= 0) {
			first_session = be64toh(lsession.id);
		}
	}

	/* I know, type mismatch */
	ret = (int) first_session;

error:
	return ret;
}

static
int attach_session(int id, int begin)
{
	struct lttng_viewer_cmd cmd;
	struct lttng_viewer_attach_session_request rq;
	struct lttng_viewer_attach_session_response rp;
	struct lttng_viewer_stream stream;
	int ret, i;

	cmd.cmd = htobe32(VIEWER_ATTACH_SESSION);
	cmd.data_size = sizeof(rq);
	cmd.cmd_version = 0;

	rq.session_id = htobe64(id);
	if (begin) {
		rq.seek = htobe32(VIEWER_SEEK_BEGINNING);
	} else {
		rq.seek = htobe32(VIEWER_SEEK_LAST);
	}

	do {
		ret = send(control_sock, &cmd, sizeof(cmd), 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		fprintf(stderr, "Error sending cmd\n");
		goto error;
	}
	do {
		ret = send(control_sock, &rq, sizeof(rq), 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		fprintf(stderr, "Error sending attach request\n");
		goto error;
	}

	do {
		ret = recv(control_sock, &rp, sizeof(rp), 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		fprintf(stderr, "Error receiving attach response\n");
		goto error;
	}
	fprintf(stderr, "  - session attach response : %u\n", be32toh(rp.status));
	if (be32toh(rp.status) != VIEWER_ATTACH_OK) {
		ret = 1;
		goto end;
	}

	session->stream_count = be32toh(rp.streams_count);
	fprintf(stderr, "  - Waiting for %" PRIu64 " streams\n", session->stream_count);
	session->streams = zmalloc(session->stream_count *
			sizeof(struct viewer_stream));
	if (!session->streams) {
		ret = -1;
		goto error;
	}

	for (i = 0; i < be32toh(rp.streams_count); i++) {
		do {
			ret = recv(control_sock, &stream, sizeof(stream), 0);
		} while (ret < 0 && errno == EINTR);
		if (ret < 0) {
			fprintf(stderr, "Error receiving stream\n");
			goto error;
		}
		fprintf(stderr, "    - stream %" PRIu64 " : %s/%s\n",
				be64toh(stream.id), stream.path_name,
				stream.channel_name);
		session->streams[i].id = be64toh(stream.id);

		session->streams[i].ctf_trace_id = be64toh(stream.ctf_trace_id);
		session->streams[i].first_read = 1;
		session->streams[i].mmap_base = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (session->streams[i].mmap_base == MAP_FAILED) {
			fprintf(stderr, "mmap error\n");
			ret = -1;
			goto error;
		}

		if (be32toh(stream.metadata_flag)) {
			session->streams[i].metadata_flag = 1;
			unlink("testlivetrace");
			mkdir("testlivetrace", S_IRWXU | S_IRWXG);
			snprintf(session->streams[i].path,
					sizeof(session->streams[i].path),
					"testlivetrace/%s",
					stream.channel_name);
			ret = open(session->streams[i].path,
					O_WRONLY | O_CREAT | O_TRUNC,
					S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
			if (ret < 0) {
				goto error;
			}
			session->streams[i].fd = ret;
		}
	}
	ret = 0;

end:
error:
	return ret;
}

#if 0
/* useful debug */
static
void dump_packet_index(struct lttng_packet_index *index)
{
	printf("      - index : %lu, %lu, %lu, %lu, %lu, %lu, %lu\n",
			be64toh(index->offset),
			be64toh(index->packet_size),
			be64toh(index->content_size),
			be64toh(index->timestamp_begin),
			be64toh(index->timestamp_end),
			be64toh(index->events_discarded),
			be64toh(index->stream_id));
}
#endif

static
int get_data_packet(int id, uint64_t offset,
		uint64_t len)
{
	struct lttng_viewer_cmd cmd;
	struct lttng_viewer_get_packet rq;
	struct lttng_viewer_trace_packet rp;
	int ret;

	cmd.cmd = htobe32(VIEWER_GET_PACKET);
	cmd.data_size = sizeof(rq);
	cmd.cmd_version = 0;

	rq.stream_id = htobe64(session->streams[id].id);
	/* Already in big endian. */
	rq.offset = offset;
	rq.len = htobe32(len);
	fprintf(stderr, "      - get_packet ");

	do {
		ret = send(control_sock, &cmd, sizeof(cmd), 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		fprintf(stderr, "Error sending cmd\n");
		goto error;
	}
	do {
		ret = send(control_sock, &rq, sizeof(rq), 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		fprintf(stderr, "Error sending get_data_packet request\n");
		goto error;
	}
	do {
		ret = recv(control_sock, &rp, sizeof(rp), 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		fprintf(stderr, "Error receiving data response\n");
		goto error;
	}
	rp.flags = be32toh(rp.flags);

	switch (be32toh(rp.status)) {
	case VIEWER_GET_PACKET_OK:
		fprintf(stderr, "OK\n");
		break;
	case VIEWER_GET_PACKET_RETRY:
		fprintf(stderr, "RETRY\n");
		ret = -1;
		goto end;
	case VIEWER_GET_PACKET_ERR:
		if (rp.flags & LTTNG_VIEWER_FLAG_NEW_METADATA) {
			fprintf(stderr, "NEW_METADATA\n");
			ret = 0;
			goto end;
		}
		fprintf(stderr, "ERR\n");
		ret = -1;
		goto end;
	default:
		fprintf(stderr, "UNKNOWN\n");
		ret = -1;
		goto end;
	}

	len = be32toh(rp.len);
	fprintf(stderr, "        - writing %" PRIu64" bytes to tracefile\n", len);
	if (len <= 0) {
		goto end;
	}

	if (len > mmap_size) {
		fprintf(stderr, "mmap_size not big enough\n");
		ret = -1;
		goto error;
	}

	do {
		ret = recv(control_sock, session->streams[id].mmap_base, len, MSG_WAITALL);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		fprintf(stderr, "Error receiving trace packet\n");
		goto error;
	}

end:
error:
	return ret;
}

/*
 * Return number of metadata bytes written or a negative value on error.
 */
static
int get_new_metadata(int id)
{
	struct lttng_viewer_cmd cmd;
	struct lttng_viewer_get_metadata rq;
	struct lttng_viewer_metadata_packet rp;
	int ret;
	uint64_t i;
	char *data = NULL;
	uint64_t len = 0;
	int metadata_stream_id = -1;

	cmd.cmd = htobe32(VIEWER_GET_METADATA);
	cmd.data_size = sizeof(rq);
	cmd.cmd_version = 0;

	/* find the metadata stream for this ctf_trace */
	for (i = 0; i < session->stream_count; i++) {
		if (session->streams[i].metadata_flag &&
				session->streams[i].ctf_trace_id ==
				session->streams[id].ctf_trace_id) {
			metadata_stream_id = i;
			break;
		}
	}
	if (metadata_stream_id < 0) {
		fprintf(stderr, "No metadata stream found\n");
		ret = -1;
		goto error;
	}

	rq.stream_id = htobe64(session->streams[metadata_stream_id].id);
	fprintf(stderr, "      - get_metadata ");

	do {
		ret = send(control_sock, &cmd, sizeof(cmd), 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		fprintf(stderr, "Error sending cmd\n");
		goto error;
	}
	do {
		ret = send(control_sock, &rq, sizeof(rq), 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		fprintf(stderr, "Error sending get_metadata request\n");
		goto error;
	}
	do {
		ret = recv(control_sock, &rp, sizeof(rp), 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		fprintf(stderr, "Error receiving metadata response\n");
		goto error;
	}
	switch (be32toh(rp.status)) {
		case VIEWER_METADATA_OK:
			fprintf(stderr, "OK\n");
			break;
		case VIEWER_NO_NEW_METADATA:
			fprintf(stderr, "NO NEW\n");
			ret = -1;
			goto end;
		case VIEWER_METADATA_ERR:
			fprintf(stderr, "ERR\n");
			ret = -1;
			goto end;
		default:
			fprintf(stderr, "UNKNOWN\n");
			ret = -1;
			goto end;
	}

	len = be64toh(rp.len);
	fprintf(stderr, "        - writing %" PRIu64" bytes to metadata\n", len);
	if (len <= 0) {
		goto end;
	}

	data = zmalloc(len);
	if (!data) {
		perror("relay data zmalloc");
		goto error;
	}
	do {
		ret = recv(control_sock, data, len, MSG_WAITALL);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		fprintf(stderr, "Error receiving trace packet\n");
		free(data);
		goto error;
	}
	do {
		ret = write(session->streams[metadata_stream_id].fd, data, len);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		free(data);
		goto error;
	}
	free(data);

	/* FIXME : bad */
	ret = (int) len;
end:
error:
	return ret;
}

/*
 * Get one index for a stream.
 */
int get_next_index(int id, struct packet_index *index)
{
	struct lttng_viewer_cmd cmd;
	struct lttng_viewer_get_next_index rq;
	struct lttng_viewer_index rp;
	int ret;

	cmd.cmd = htobe32(VIEWER_GET_NEXT_INDEX);
	cmd.data_size = sizeof(rq);
	cmd.cmd_version = 0;

	fprintf(stderr, "  - get next index for stream %" PRIu64 "\n",
			session->streams[id].id);
	rq.stream_id = htobe64(session->streams[id].id);

retry:
	do {
		ret = send(control_sock, &cmd, sizeof(cmd), 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		fprintf(stderr, "Error sending cmd\n");
		goto error;
	}
	do {
		ret = send(control_sock, &rq, sizeof(rq), 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		fprintf(stderr, "Error sending get_next_index request\n");
		goto error;
	}
	do {
		ret = recv(control_sock, &rp, sizeof(rp), 0);
	} while (ret < 0 && errno == EINTR);
	if (ret < 0) {
		fprintf(stderr, "Error receiving index response\n");
		goto error;
	}
	fprintf(stderr, "    - reply : %u ", be32toh(rp.status));

	rp.flags = be32toh(rp.flags);

	switch (be32toh(rp.status)) {
	case VIEWER_INDEX_INACTIVE:
		fprintf(stderr, "(INACTIVE)\n");
		memset(index, 0, sizeof(struct packet_index));
		index->timestamp_end = be64toh(rp.timestamp_end);
		break;
	case VIEWER_INDEX_OK:
		fprintf(stderr, "(OK), need metadata update : %u\n",
				rp.flags & LTTNG_VIEWER_FLAG_NEW_METADATA);
		index->offset = be64toh(rp.offset);
		index->packet_size = be64toh(rp.packet_size);
		index->content_size = be64toh(rp.content_size);
		index->timestamp_begin = be64toh(rp.timestamp_begin);
		index->timestamp_end = be64toh(rp.timestamp_end);
		index->events_discarded = be64toh(rp.events_discarded);

		if (rp.flags & LTTNG_VIEWER_FLAG_NEW_METADATA) {
			fprintf(stderr, "NEW METADATA NEEDED\n");
			ret = get_new_metadata(id);
			if (ret < 0) {
				goto error;
			}
		}
		break;
	case VIEWER_INDEX_RETRY:
		fprintf(stderr, "(RETRY)\n");
		sleep(1);
		goto retry;
	case VIEWER_INDEX_HUP:
		fprintf(stderr, "(HUP)\n");
		session->streams[id].id = -1ULL;
		session->streams[id].fd = -1;
		break;
	case VIEWER_INDEX_ERR:
		fprintf(stderr, "(ERR)\n");
		ret = -1;
		goto error;
	default:
		fprintf(stderr, "SHOULD NOT HAPPEN\n");
		ret = -1;
		goto error;
	}

error:
	return ret;
}

void ctf_live_packet_seek(struct bt_stream_pos *stream_pos, size_t index,
		int whence)
{
	struct ctf_stream_pos *pos;
	struct ctf_file_stream *file_stream;
	struct packet_index packet_index;
	int ret;

	pos = ctf_pos(stream_pos);
	file_stream = container_of(pos, struct ctf_file_stream, pos);

	fprintf(stderr, "BT GET_NEXT_INDEX %d\n", pos->fd);
	ret = get_next_index(pos->fd, &packet_index);
	if (ret < 0) {
		fprintf(stderr, "get_next_index failed\n");
		return;
	}

	pos->packet_size = packet_index.packet_size;
	pos->content_size = packet_index.content_size;
	pos->mmap_base_offset = 0;
	pos->offset = 0;
	if (packet_index.offset == EOF) {
		pos->offset = EOF;
	} else {
		pos->offset = 0;
	}

	file_stream->parent.cycles_timestamp = packet_index.timestamp_end;
	file_stream->parent.real_timestamp = ctf_get_real_timestamp(
			&file_stream->parent, packet_index.timestamp_end);

	if (pos->packet_size == 0) {
		goto end;
	}

	fprintf(stderr, "BT GET_DATA_PACKET\n");
	ret = get_data_packet(pos->fd, be64toh(packet_index.offset),
			packet_index.packet_size / CHAR_BIT);
	if (ret < 0) {
		fprintf(stderr, "get_data_packet failed");
		return;
	}

	fprintf(stderr, "BT MMAP %d\n", pos->fd);
	fprintf(stderr, "packet_size : %lu, offset %lu, content_size %lu, timestamp_end : %lu, real : %lu\n",
			packet_index.packet_size,
			packet_index.offset,
			packet_index.content_size,
			packet_index.timestamp_end,
			ctf_get_real_timestamp(
				&file_stream->parent, packet_index.timestamp_end));
	if (!pos->base_mma) {
		pos->base_mma = zmalloc(sizeof(*pos->base_mma));
		if (!pos->base_mma) {
			fprintf(stderr, "alloc pos->base_mma\n");
			return;
		}
	}

	mmap_align_set_addr(pos->base_mma, session->streams[pos->fd].mmap_base);
	if (pos->base_mma == MAP_FAILED) {
		perror("Error mmaping");
		return;
	}

	/* update trace_packet_header and stream_packet_context */
	if (pos->prot != PROT_WRITE && file_stream->parent.trace_packet_header) {
		/* Read packet header */
		ret = generic_rw(&pos->parent, &file_stream->parent.trace_packet_header->p);
		assert(!ret);
	}
	if (pos->prot != PROT_WRITE && file_stream->parent.stream_packet_context) {
		/* Read packet context */
		ret = generic_rw(&pos->parent, &file_stream->parent.stream_packet_context->p);
		assert(!ret);
	}

end:
	return;
}

int open_trace(struct bt_context **bt_ctx)
{
	struct bt_mmap_stream *new_mmap_stream;
	struct bt_mmap_stream_list mmap_list;
	FILE *metadata_fp = NULL;
	int i;
	int ret = 0;

	*bt_ctx = bt_context_create();
	BT_INIT_LIST_HEAD(&mmap_list.head);

	for (i = 0; i < session->stream_count; i++) {
		int total_metadata = 0;

		if (!session->streams[i].metadata_flag) {
			new_mmap_stream = zmalloc(sizeof(struct bt_mmap_stream));
			/*
			 * The FD is unused when we handle manually the
			 * packet seek, so we store here the ID of the
			 * stream in our stream list to be able to use it
			 * later.
			 */
			new_mmap_stream->fd = i;
			bt_list_add(&new_mmap_stream->list, &mmap_list.head);
		} else {
			/* Get all possible metadata before starting */
			do {
				ret = get_new_metadata(i);
				if (ret > 0) {
					total_metadata += ret;
				}
			} while (ret > 0 || total_metadata == 0);
			metadata_fp = fopen(session->streams[i].path, "r");
		}
	}

	if (!metadata_fp) {
		fprintf(stderr, "No metadata stream opened\n");
		goto end;
	}

	ret = bt_context_add_trace(*bt_ctx, NULL, "ctf",
			ctf_live_packet_seek, &mmap_list, metadata_fp);
	if (ret < 0) {
		fprintf(stderr, "Error adding trace\n");
		goto end;
	}

	/*
	begin_pos.type = BT_SEEK_BEGIN;
	iter = bt_ctf_iter_create(bt_ctx, &begin_pos, NULL);
	while ((event = bt_ctf_iter_read_event(iter)) != NULL) {
		if (!skip) {
			ret = sout->parent.event_cb(&sout->parent, event->parent->stream);
			if (ret) {
				fprintf(stderr, "[error] Writing event failed.\n");
				goto end;
			}
		}

		ret = bt_iter_next(bt_ctf_get_iter(iter));
		if (ret < 0) {
			goto end;
		} else if (ret == EAGAIN) {
			skip = 1;
			continue;
		}
		skip = 0;
	}
	*/

end:
	return ret;
}

int setup_network_live(char *hostname, int begin)
{
	int ret;
	int session_id;

	session = zmalloc(sizeof(struct live_session));
	if (!session) {
		goto error;
	}

	ret = connect_viewer(hostname);
	if (ret < 0) {
		goto error;
	}
	fprintf(stderr, "* Connected\n");

	fprintf(stderr, "* Establish connection and version check\n");
	ret = establish_connection();
	if (ret < 0) {
		goto error;
	}

	fprintf(stderr, "* List sessions\n");
	ret = list_sessions();
	if (ret < 0) {
		fprintf(stderr, "* List error\n");
		goto error;
	} else if (ret == 0) {
		fprintf(stderr, "* No session to attach to, exiting\n");
		ret = 0;
		goto end;
	}
	session_id = ret;

	do {
		fprintf(stderr, "* Attach session %d\n", ret);
		ret = attach_session(session_id, begin);
		if (ret < 0) {
			goto error;
		}
	} while (session->stream_count == 0);

end:
	return 0;

error:
	free(session->streams);
	fprintf(stderr, "* Exiting %d\n", ret);
	return ret;
}

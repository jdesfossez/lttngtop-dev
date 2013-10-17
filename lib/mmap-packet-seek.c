#include "babeltrace/ctf/types.h"
#include "babeltrace/ctf/metadata.h"

void ctf_move_mmap_pos_slow(struct ctf_stream_pos *pos, size_t offset, int whence)
{
	struct ctf_file_stream *file_stream =
		container_of(pos, struct ctf_file_stream, pos);
	int ret, err, i;
	off_t off;
	struct packet_index *index;
	int len_index;
	struct mmap_stream *iter, *tmp;
	struct mmap_stream tmp_snapshot;

	/* first time we have to mmap the region */
	if (pos->mmap_len == 0) {
		/* get the len of the mmap region */
		ret = kernctl_get_mmap_len(pos->fd, &pos->mmap_len);
		if (ret != 0) {
			ret = errno;
			perror("kernctl_get_mmap_len");
			goto end;
		}
		pos->mmap_real_base = mmap(NULL, pos->mmap_len, PROT_READ, MAP_PRIVATE, pos->fd, 0);
		if (pos->mmap_real_base == MAP_FAILED) {
			perror("Error mmaping");
			ret = -1;
		}
	}

	if (pos->base) {
		/* FIXME : put_subbuf should work but fails after nb_subbuf get + put */
		ret = kernctl_put_next_subbuf(pos->fd);
		if (ret != 0) {
			ret = errno;
			perror("kernctl_put_subbuf");
		}
		pos->base = NULL;
	}

next_snapshot:
	tmp_snapshot.kconsumerd_fd = 0;
	for (i = 0; i < available_snapshots->len; i++) {
		tmp = g_ptr_array_index(available_snapshots, 0);
		if (tmp->kconsumerd_fd->wait_fd == pos->fd) {
			tmp_snapshot.last_pos = tmp->last_pos;
			tmp_snapshot.kconsumerd_fd = tmp->kconsumerd_fd;
			g_ptr_array_remove_index(available_snapshots, i);
			free(tmp);
			break;
		}
	}
	if (tmp_snapshot.kconsumerd_fd == 0) {
		pos->offset = EOF;
		return;
	}
//	fprintf(stderr,"READING FROM SNAPSHOT ON FD %d at %lu\n",
//			tmp_snapshot.kconsumerd_fd->wait_fd, tmp_snapshot.last_pos);
	ret = kernctl_get_subbuf(tmp_snapshot.kconsumerd_fd->wait_fd, &tmp_snapshot.last_pos);
	if (ret != 0) {
		ret = errno;
		perror("kernctl_get_subbuf");
		goto next_snapshot;
	}

	ret = kernctl_get_mmap_read_offset(pos->fd, &(pos->mmap_offset));
	if (ret != 0) {
		ret = errno;
		perror("kernctl_get_mmap_read_offset");
		goto end;
	}

	/* read only the data in the subbuffer */
	err = kernctl_get_subbuf_size(pos->fd, &pos->content_size);
	if (err != 0) {
		ret = errno;
		perror("Getting sub-buffer len failed.");
		goto end;
	}
	/* bits vs bytes */
	pos->content_size *= CHAR_BIT;
	/* read the whole subbuffer */
	err = kernctl_get_padded_subbuf_size(pos->fd, &pos->packet_size);
	if (err != 0) {
		ret = errno;
		perror("Getting sub-buffer len failed.");
		goto end;
	}
	/* bits vs bytes */
	pos->packet_size *= CHAR_BIT;

	pos->offset = 0;    /* will read headers */

	/* map new base. Need mapping length from header. */
	pos->base = pos->mmap_real_base + pos->mmap_offset;

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

	/* read timestamp begin from header */
	len_index = struct_declaration_lookup_field_index(
			file_stream->parent.stream_packet_context->declaration,
			g_quark_from_static_string("timestamp_begin"));
	if (len_index >= 0) {
		struct definition_integer *defint;
		struct definition *field;

		field = struct_definition_get_field_from_index(
				file_stream->parent.stream_packet_context, len_index);
		assert(field->declaration->id == CTF_TYPE_INTEGER);
		defint = container_of(field, struct definition_integer, p);
		assert(defint->declaration->signedness == FALSE);
		file_stream->parent.timestamp = defint->value._unsigned;
//		fprintf(stderr, "READ TIMESTAMP : %lu\n", file_stream->parent.timestamp);
	}


end:
	return;
}


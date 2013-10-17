#ifdef LTTNGTOP_MMAP_LIVE

static
ssize_t read_subbuffer(struct lttng_consumer_stream *kconsumerd_fd,
		struct lttng_consumer_local_data *ctx)
{
	unsigned long len;
	int err;
	long ret = 0;
	int infd = helper_get_lttng_consumer_stream_wait_fd(kconsumerd_fd);

	if (helper_get_lttng_consumer_stream_output(kconsumerd_fd) == LTTNG_EVENT_SPLICE) {
		/* Get the next subbuffer */
		err = helper_kernctl_get_next_subbuf(infd);
		if (err != 0) {
			ret = errno;
			perror("Reserving sub buffer failed (everything is normal, "
					"it is due to concurrency)");
			goto end;
		}
		/* read the whole subbuffer */
		err = helper_kernctl_get_padded_subbuf_size(infd, &len);
		if (err != 0) {
			ret = errno;
			perror("Getting sub-buffer len failed.");
			goto end;
		}

		/* splice the subbuffer to the tracefile */
		ret = helper_lttng_consumer_on_read_subbuffer_splice(ctx, kconsumerd_fd, len, 0);
		if (ret < 0) {
			/*
			 * display the error but continue processing to try
			 * to release the subbuffer
			 */
			fprintf(stderr,"Error splicing to tracefile\n");
		}
		err = helper_kernctl_put_next_subbuf(infd);
		if (err != 0) {
			ret = errno;
			perror("Reserving sub buffer failed (everything is normal, "
					"it is due to concurrency)");
			goto end;
		}
		sem_post(&metadata_available);
	}

end:
	return 0;
}

static
int on_update_fd(int key, uint32_t state)
{
	/* let the lib handle the metadata FD */
	if (key == sessiond_metadata)
		return 0;
	return 1;
}

static
int on_recv_fd(struct lttng_consumer_stream *kconsumerd_fd)
{
	int ret;
	struct bt_mmap_stream *new_mmap_stream;

	/* Opening the tracefile in write mode */
	if (helper_get_lttng_consumer_stream_path_name(kconsumerd_fd) != NULL) {
		ret = open(helper_get_lttng_consumer_stream_path_name(kconsumerd_fd),
				O_WRONLY|O_CREAT|O_TRUNC, S_IRWXU|S_IRWXG|S_IRWXO);
		if (ret < 0) {
			perror("open");
			goto end;
		}
		helper_set_lttng_consumer_stream_out_fd(kconsumerd_fd, ret);
	}

	if (helper_get_lttng_consumer_stream_output(kconsumerd_fd) == LTTNG_EVENT_MMAP) {
		new_mmap_stream = malloc(sizeof(struct bt_mmap_stream));
		new_mmap_stream->fd = helper_get_lttng_consumer_stream_wait_fd(
				kconsumerd_fd);
		bt_list_add(&new_mmap_stream->list, &mmap_list.head);

		g_ptr_array_add(lttng_consumer_stream_array, kconsumerd_fd);
		/* keep mmap FDs internally */
		ret = 1;
	} else {
		consumerd_metadata = helper_get_lttng_consumer_stream_wait_fd(kconsumerd_fd);
		sessiond_metadata = helper_get_lttng_consumer_stream_key(kconsumerd_fd);
		ret = 0;
	}

	reload_trace = 1;

end:
	return ret;
}

static
void live_consume(struct bt_context **bt_ctx)
{
	int ret;
	FILE *metadata_fp;

	sem_wait(&metadata_available);
	if (access("/tmp/livesession/kernel/metadata", F_OK) != 0) {
		fprintf(stderr,"no metadata\n");
		goto end;
	}
	metadata_fp = fopen("/tmp/livesession/kernel/metadata", "r");

	*bt_ctx = bt_context_create();
	ret = bt_context_add_trace(*bt_ctx, NULL, "ctf",
			lttngtop_ctf_packet_seek, &mmap_list, metadata_fp);
	if (ret < 0) {
		printf("Error adding trace\n");
		goto end;
	}

end:
	return;
}

static
int setup_consumer(char *command_sock_path, pthread_t *threads,
		struct lttng_consumer_local_data *ctx)
{
	int ret = 0;

	ctx = helper_lttng_consumer_create(HELPER_LTTNG_CONSUMER_KERNEL,
		read_subbuffer, NULL, on_recv_fd, on_update_fd);
	if (!ctx)
		goto end;

	unlink(command_sock_path);
	helper_lttng_consumer_set_command_sock_path(ctx, command_sock_path);
	helper_lttng_consumer_init();

	/* Create the thread to manage the receive of fd */
	ret = pthread_create(&threads[0], NULL, helper_lttng_consumer_thread_sessiond_poll,
			(void *) ctx);
	if (ret != 0) {
		perror("pthread_create receive fd");
		goto end;
	}
	/* Create thread to manage the polling/writing of traces */
	ret = pthread_create(&threads[1], NULL, helper_lttng_consumer_thread_metadata_poll,
			(void *) ctx);
	if (ret != 0) {
		perror("pthread_create poll fd");
		goto end;
	}

end:
	return ret;
}

static
int enable_kprobes(struct lttng_handle *handle, char *channel_name)
{
	struct lttng_event ev;
	struct kprobes *kprobe;
	int ret = 0;
	int i;

	for (i = 0; i < lttngtop.kprobes_table->len; i++) {
		kprobe = g_ptr_array_index(lttngtop.kprobes_table, i);

		memset(&ev, '\0', sizeof(struct lttng_event));
		ev.type = LTTNG_EVENT_PROBE;
		if (kprobe->symbol_name)
			sprintf(ev.attr.probe.symbol_name, "%s", kprobe->symbol_name);
		sprintf(ev.name, "%s", kprobe->probe_name);
		ev.attr.probe.addr = kprobe->probe_addr;
		ev.attr.probe.offset = kprobe->probe_offset;
		if ((ret = lttng_enable_event(handle, &ev, channel_name)) < 0) {
			fprintf(stderr,"error enabling kprobes : %s\n",
					helper_lttcomm_get_readable_code(ret));
			goto end;
		}
	}

end:
	return ret;
}

static
int setup_live_tracing()
{
	struct lttng_domain dom;
	struct lttng_channel chan;
	char *channel_name = "mmapchan";
	struct lttng_event ev;
	int ret = 0;
	char *command_sock_path = "/tmp/consumerd_sock";
	static pthread_t threads[2]; /* recv_fd, poll */
	struct lttng_event_context kctxpid, kctxcomm, kctxppid, kctxtid,
				   kctxperf1, kctxperf2;

	struct lttng_handle *handle;

	BT_INIT_LIST_HEAD(&mmap_list.head);

	lttng_consumer_stream_array = g_ptr_array_new();

	if ((ret = setup_consumer(command_sock_path, threads, ctx)) < 0) {
		fprintf(stderr,"error setting up consumer\n");
		goto error;
	}

	available_snapshots = g_ptr_array_new();

	/* setup the session */
	dom.type = LTTNG_DOMAIN_KERNEL;

	ret = unlink("/tmp/livesession");

	lttng_destroy_session("test");
	if ((ret = lttng_create_session("test", "/tmp/livesession")) < 0) {
		fprintf(stderr,"error creating the session : %s\n",
				helper_lttcomm_get_readable_code(ret));
		goto error;
	}

	if ((handle = lttng_create_handle("test", &dom)) == NULL) {
		fprintf(stderr,"error creating handle\n");
		goto error_session;
	}

	/*
	 * FIXME : need to let the
	 * helper_lttng_consumer_thread_receive_fds create the
	 * socket.
	 * Cleaner solution ?
	 */
	while (access(command_sock_path, F_OK)) {
		sleep(0.1);
	}

	if ((ret = lttng_register_consumer(handle, command_sock_path)) < 0) {
		fprintf(stderr,"error registering consumer : %s\n",
				helper_lttcomm_get_readable_code(ret));
		goto error_session;
	}

	strcpy(chan.name, channel_name);
	chan.attr.overwrite = 0;
	if (opt_tid && opt_textdump) {
		chan.attr.subbuf_size = 32768;
		chan.attr.num_subbuf = 8;
	} else {
		//chan.attr.subbuf_size = 1048576; /* 1MB */
		chan.attr.subbuf_size = 2097152; /* 1MB */
		chan.attr.num_subbuf = 4;
	}
	chan.attr.switch_timer_interval = 0;
	chan.attr.read_timer_interval = 200;
	chan.attr.output = LTTNG_EVENT_MMAP;

	if ((ret = lttng_enable_channel(handle, &chan)) < 0) {
		fprintf(stderr,"error creating channel : %s\n",
				helper_lttcomm_get_readable_code(ret));
		goto error_session;
	}

	memset(&ev, '\0', sizeof(struct lttng_event));
	ev.type = LTTNG_EVENT_TRACEPOINT;
	sprintf(ev.name, "sched_switch");
	if ((ret = lttng_enable_event(handle, &ev, channel_name)) < 0) {
		fprintf(stderr,"error enabling event %s : %s\n",
				ev.name,
				helper_lttcomm_get_readable_code(ret));
		goto error_session;
	}
	sprintf(ev.name, "sched_process_free");
	if ((ret = lttng_enable_event(handle, &ev, channel_name)) < 0) {
		fprintf(stderr,"error enabling event %s : %s\n",
				ev.name,
				helper_lttcomm_get_readable_code(ret));
		goto error_session;
	}
	sprintf(ev.name, "lttng_statedump_process_state");
	if ((ret = lttng_enable_event(handle, &ev, channel_name)) < 0) {
		fprintf(stderr,"error enabling event %s : %s\n",
				ev.name,
				helper_lttcomm_get_readable_code(ret));
		goto error_session;
	}
	sprintf(ev.name, "lttng_statedump_file_descriptor");
	if ((ret = lttng_enable_event(handle, &ev, channel_name)) < 0) {
		fprintf(stderr,"error enabling event %s : %s\n",
				ev.name,
				helper_lttcomm_get_readable_code(ret));
		goto error_session;
	}

	memset(&ev, '\0', sizeof(struct lttng_event));
	ev.type = LTTNG_EVENT_SYSCALL;
	if ((ret = lttng_enable_event(handle, &ev, channel_name)) < 0) {
		fprintf(stderr,"error enabling syscalls : %s\n",
				helper_lttcomm_get_readable_code(ret));
		goto error_session;
	}

	if (lttngtop.kprobes_table) {
		ret = enable_kprobes(handle, channel_name);
		if (ret < 0) {
			goto error_session;
		}
	}

	kctxperf1.ctx = LTTNG_EVENT_CONTEXT_PERF_COUNTER;
	kctxperf1.u.perf_counter.type = 0; /* PERF_TYPE_HARDWARE */
	kctxperf1.u.perf_counter.config = 5; /* PERF_COUNT_HW_BRANCH_MISSES */
	sprintf(kctxperf1.u.perf_counter.name, "perf_branch_misses");
	ret = lttng_add_context(handle, &kctxperf1, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "error enabling context %s\n",
				kctxtid.u.perf_counter.name);
	}

	kctxperf2.ctx = LTTNG_EVENT_CONTEXT_PERF_COUNTER;
	kctxperf2.u.perf_counter.type = 1; /* PERF_TYPE_SOFTWARE */
	kctxperf2.u.perf_counter.config = 6; /* PERF_COUNT_SW_PAGE_FAULTS_MAJ */
	sprintf(kctxperf2.u.perf_counter.name, "perf_major_faults");
	ret = lttng_add_context(handle, &kctxperf2, NULL, NULL);
	if (ret < 0) {
		fprintf(stderr, "error enabling context %s\n",
				kctxtid.u.perf_counter.name);
	}

	kctxpid.ctx = LTTNG_EVENT_CONTEXT_PID;
	lttng_add_context(handle, &kctxpid, NULL, NULL);
	kctxtid.ctx = LTTNG_EVENT_CONTEXT_TID;
	lttng_add_context(handle, &kctxtid, NULL, NULL);
	kctxppid.ctx = LTTNG_EVENT_CONTEXT_PPID;
	lttng_add_context(handle, &kctxppid, NULL, NULL);
	kctxcomm.ctx = LTTNG_EVENT_CONTEXT_PROCNAME;
	lttng_add_context(handle, &kctxcomm, NULL, NULL);
	kctxpid.ctx = LTTNG_EVENT_CONTEXT_VPID;
	lttng_add_context(handle, &kctxpid, NULL, NULL);
	kctxtid.ctx = LTTNG_EVENT_CONTEXT_VTID;
	lttng_add_context(handle, &kctxtid, NULL, NULL);
	kctxtid.ctx = LTTNG_EVENT_CONTEXT_HOSTNAME;
	lttng_add_context(handle, &kctxtid, NULL, NULL);


	if ((ret = lttng_start_tracing("test")) < 0) {
		fprintf(stderr,"error starting tracing : %s\n",
				helper_lttcomm_get_readable_code(ret));
		goto error_session;
	}

	helper_kernctl_buffer_flush(consumerd_metadata);

	/* block until metadata is ready */
	sem_init(&metadata_available, 0, 0);

	return 0;

error_session:
	lttng_destroy_session("test");
error:
	return -1;
}

int mmap_live_loop(struct bt_context *bt_ctx,
		struct bt_mmap_stream_list mmap_list)
{
	struct bt_mmap_stream *mmap_info;

	ret = setup_live_tracing();
	if (ret < 0) {
		goto end;
	}

	while (!quit) {
		reload_trace = 0;
		live_consume(&bt_ctx);
		ret = check_requirements(bt_ctx);
		if (ret < 0) {
			fprintf(stderr, "[error] some mandatory contexts were missing, exiting.\n");
			goto end;
		}
		iter_trace(bt_ctx);
		/*
		 * FIXME : pb with cleanup in libbabeltrace
		 ret = bt_context_remove_trace(bt_ctx, 0);
		 if (ret != 0) {
		 fprintf(stderr, "error removing trace\n");
		 goto error;
		 }
		 */
		if (bt_ctx) {
			bt_context_put(bt_ctx);
		}

		/*
		 * since we receive all FDs every time there is an
		 * update and the FD number is different every time,
		 * we don't know which one are valid.
		 * so we check if all FDs are usable with a simple
		 * ioctl call.
		 */
		bt_list_for_each_entry(mmap_info, &mmap_list.head, list) {
			unsigned long mmap_len;

			ret = helper_kernctl_get_mmap_len(mmap_info->fd, &mmap_len);
			if (ret != 0) {
				bt_list_del(&mmap_info->list);
			}
		}
		sem_post(&metadata_available);
	}

}

void mmap_live_flush(struct bt_mmap_stream_list mmap_list)
{
	struct bt_mmap_stream *mmap_info;

	bt_list_for_each_entry(mmap_info, &mmap_list.head, list)
		helper_kernctl_buffer_flush(mmap_info->fd);
}
#endif /* LTTNGTOP_MMAP_LIVE */

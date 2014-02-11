#!/bin/bash

# Just create the live session on localhost

SESSION_NAME="lttngtop-live-simple"

lttng create $SESSION_NAME --live 1000000 -U net://localhost
lttng enable-event -s $SESSION_NAME -k lttng_statedump_start,lttng_statedump_end,lttng_statedump_process_state,lttng_statedump_file_descriptor,lttng_statedump_vm_map,lttng_statedump_network_interface,lttng_statedump_interrupt,sched_process_free,sched_switch,sched_process_fork
lttng enable-event -s $SESSION_NAME -k --syscall -a
lttng add-context -s $SESSION_NAME -k -t pid -t procname -t tid -t ppid -t perf:cache-misses -t perf:major-faults -t perf:branch-load-misses
lttng start $SESSION_NAME

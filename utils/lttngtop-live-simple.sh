#!/bin/bash

# Setup a live LTTng session on localhost

SESSION_NAME="lttngtop-live-simple"
DEBUG=">/dev/null"

pgrep -u root lttng-sessiond >/dev/null
if test $? != 0; then
	echo "Starting lttng-sessiond as root (trying sudo, start manually if \
it fails)"
	sudo lttng-sessiond -d
	if test $? != 0; then
		exit 1
	fi
fi

pgrep lttng-relayd >/dev/null
if test $? != 0; then
	echo "Starting lttng-relayd as your current user, start manually if \
it fails"
	lttng-relayd -d
	if test $? != 0; then
		exit 1
	fi
fi

SUDO=""
groups|grep tracing >/dev/null
if test $? != 0; then
	echo "You are not a member of the tracing group, so you need root \
access, the script will try with sudo"
	SUDO="sudo"
fi

# check if lttng command if in the path
# check if the user can execute the command (with sudo if not in tracing group)
# check if lttng-modules is installed
$SUDO lttng list -k | grep sched_switch >/dev/null
if test $? != 0; then
	echo "Something went wrong executing \"$SUDO lttng list -k | grep sched_switch\", \
try to fix the problem manually and then start the script again"
fi

lttng create $SESSION_NAME --live 1000000 -U net://localhost >/dev/null
[[ $? != 0 ]] && exit 2
lttng enable-event -s $SESSION_NAME -k lttng_statedump_start,lttng_statedump_end,lttng_statedump_process_state,lttng_statedump_file_descriptor,lttng_statedump_vm_map,lttng_statedump_network_interface,lttng_statedump_interrupt,sched_process_free,sched_switch >/dev/null
[[ $? != 0 ]] && exit 2
lttng enable-event -s $SESSION_NAME -k --syscall -a >/dev/null
[[ $? != 0 ]] && exit 2
lttng add-context -s $SESSION_NAME -k -t pid -t procname -t tid -t ppid -t perf:cache-misses -t perf:major-faults -t perf:branch-load-misses >/dev/null
[[ $? != 0 ]] && exit 2
lttng start $SESSION_NAME >/dev/null
[[ $? != 0 ]] && exit 2

s=$(lttngtop -r net://localhost | grep $SESSION_NAME)
if test $? != 0; then
	echo "Problem executing lttngtop -r net://localhost | grep $SESSION_NAME"
	exit 1
fi

lttngtop -r $(echo $s|cut -d' ' -f1)

lttng destroy $SESSION_NAME >/dev/null
echo -n "Destroy $HOME/lttng-traces/$HOSTNAME/${SESSION_NAME}* (Y/n) ? "
read a
if test $a = 'y' -o $a = 'Y'; then
	rm -rf $HOME/lttng-traces/$HOSTNAME/${SESSION_NAME}*
fi

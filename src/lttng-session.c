#define _GNU_SOURCE         /* See feature_test_macros(7) */
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>

#define event_list "lttng_statedump_start,lttng_statedump_end," \
	"lttng_statedump_process_state,lttng_statedump_file_descriptor," \
	"lttng_statedump_vm_map,lttng_statedump_network_interface," \
	"lttng_statedump_interrupt,sched_process_free," \
	"sched_switch,sched_process_fork"
#define context_list "-t pid -t procname -t tid -t ppid "

static
int check_or_start_sessiond()
{
	int ret;
	int sudo = 0;

	ret = system("pgrep -u root lttng-sessiond >/dev/null");
	if (ret == 0)
		goto end;

	if (getuid() != 0) {
		fprintf(stderr, "Trying to start lttng-sessiond with sudo\n");
		ret = system("sudo -l lttng-sessiond >/dev/null");
		if (ret < 0) {
			fprintf(stderr, "[error] You are not root and not "
					"allowed by sudo to start lttng-sessiond\n");
			ret = -1;
			goto end;
		}
		ret = system("sudo -l lttng >/dev/null");
		if (ret < 0) {
			fprintf(stderr, "[error] You are not root and not "
					"allowed by sudo to use lttng\n");
			ret = -1;
			goto end;
		}
		sudo = 1;
	}

	if (sudo)
		ret = system("sudo lttng-sessiond -d");
	else
		ret = system("lttng-sessiond -d");

	if (ret != 0) {
		fprintf(stderr, "Error starting lttng-sessiond as root\n");
		ret = -1;
		goto end;
	}

end:
	return ret;
}

static
int check_or_start_relayd()
{
	int ret;

	ret = system("pgrep lttng-relayd >/dev/null");
	if (ret == 0)
		goto end;

	ret = system("lttng-relayd -d");
	if (ret != 0) {
		fprintf(stderr, "Error starting lttng-relayd\n");
		ret = -1;
		goto end;
	}

end:
	return ret;
}

/*
 * Return 0 if in tracing group or root, 1 if sudo is needed (and working),
 * a negative value on error.
 */
static
int check_tracing_group()
{
	int ret;

	ret = getuid();
	if (ret == 0)
		goto end;

	ret = system("groups|grep tracing >/dev/null");
	if (ret == 0) {
		goto end;
	}

	ret = system("sudo lttng --version >/dev/null");
	if (ret != 0) {
		fprintf(stderr, "Error executing lttng with sudo, you need to "
				"be root or in the \"tracing\" group to start "
				"kernel tracing\n");
		ret = -1;
		goto end;
	} else {
		ret = 1;
	}

end:
	return ret;
}

static
int check_lttng_modules(int sudo)
{
	int ret;

	if (sudo) {
		ret = system("sudo lttng list -k | grep sched_switch >/dev/null");
	} else {
		ret = system("lttng list -k | grep sched_switch >/dev/null");
	}
	if (ret != 0) {
		fprintf(stderr, "Error listing kernel events, "
				"lttng-modules might not be installed\n");
		goto end;
	}

end:
	return ret;
}

static
int check_requirements(int *sudo)
{
	int ret;

	ret = check_or_start_sessiond();
	if (ret < 0)
		goto end;
	ret = check_or_start_relayd();
	if (ret < 0)
		goto end;
	ret = check_tracing_group();
	if (ret < 0)
		goto end;
	else if (ret == 1)
		*sudo = 1;

	ret = check_lttng_modules(*sudo);
	if (ret < 0)
		goto end;
end:
	return ret;
}

/*
 * Allocate a random string, must be freed by the caller.
 */
static
char *random_session_name()
{
	uint64_t id;
	char *str = NULL;
	int ret;

	FILE *f = fopen( "/dev/urandom", "r");
	if (!f) {
		perror("fopen");
		goto end;
	}

	ret = fread(&id, 1, sizeof(uint64_t), f);
	if (ret < sizeof(id)) {
		perror("fread");
		goto end;
	}

	ret = asprintf(&str, "lttngtop-%" PRIu64, id);
	if (ret < 0) {
		fprintf(stderr, "Error allocating session name");
		str = NULL;
		goto end;
	}

	ret = fclose(f);
	if (ret != 0) {
		perror("fclose");
		goto end;
	}

end:
	return str;
}

static
int check_session_name(char *name, int sudo)
{
	int ret;
	char cmd[1024];

	ret = sprintf(cmd, "%s lttng list | grep %s >/dev/null",
			(sudo) ? "sudo" : " ", name);
	if (ret < 0) {
		fprintf(stderr, "Allocating cmd\n");
		goto end;
	}

	ret = (system(cmd));
	if (ret == 0) {
		fprintf(stderr, "Error: session %s already exist, either we "
				"are not random enough or something is "
				"really wrong\n", name);
		ret = -1;
		goto end;
	}

end:
	return ret;
}

static
int local_session(char *name, int sudo)
{
	int ret;
	char cmd[1024];

	ret = sprintf(cmd, "%s lttng create %s >/dev/null",
			(sudo) ? "sudo" : " ", name);
	if (ret < 0) {
		fprintf(stderr, "Allocating cmd\n");
		goto end;
	}
	ret = (system(cmd));
	if (ret != 0) {
		fprintf(stderr, "Error: creating the session\n");
		ret = -1;
		goto end;
	}

end:
	return ret;
}

static
int live_local_session(char *name, int sudo)
{
	int ret;
	char cmd[1024];

	ret = sprintf(cmd, "%s lttng create %s --live 1000000 -U net://localhost >/dev/null",
			(sudo) ? "sudo" : " ", name);
	if (ret < 0) {
		fprintf(stderr, "Allocating cmd\n");
		goto end;
	}
	ret = (system(cmd));
	if (ret != 0) {
		fprintf(stderr, "Error: creating the session\n");
		ret = -1;
		goto end;
	}

end:
	return ret;
}

static
int enable_events(char *name, int sudo)
{
	int ret;
	char cmd[1024];

	ret = sprintf(cmd, "%s lttng enable-event -s %s -k %s >/dev/null",
			(sudo) ? "sudo" : " ", name, event_list);
	if (ret < 0) {
		fprintf(stderr, "Allocating cmd\n");
		goto end;
	}

	ret = (system(cmd));
	if (ret != 0) {
		fprintf(stderr, "Error: enabling events\n");
		ret = -1;
		goto end;
	}

end:
	return ret;
}

static
int add_contexts(char *name, int sudo)
{
	int ret;
	char cmd[1024];

	ret = sprintf(cmd, "%s lttng add-context -s %s -k %s >/dev/null",
			(sudo) ? "sudo" : " ", name, context_list);
	if (ret < 0) {
		fprintf(stderr, "allocating cmd\n");
		goto end;
	}

	ret = (system(cmd));
	if (ret != 0) {
		fprintf(stderr, "error: adding contexts\n");
		ret = -1;
		goto end;
	}

end:
	return ret;
}

static
int start(char *name, int sudo, int local, int print)
{
	int ret;
	char cmd[1024];

	ret = sprintf(cmd, "%s lttng start %s >/dev/null",
			(sudo) ? "sudo" : " ", name);
	if (ret < 0) {
		fprintf(stderr, "allocating cmd\n");
		goto end;
	}

	ret = (system(cmd));
	if (ret != 0) {
		fprintf(stderr, "error: starting the session %s\n", name);
		ret = -1;
		goto end;
	}

	if (!print)
		goto end;

	if (local) {
		ret = sprintf(cmd, "%s lttng list|grep %s|cut -d'(' -f2|cut -d ')' -f1",
				(sudo) ? "sudo" : " ", name);
	} else {
		ret = sprintf(cmd, "babeltrace -i lttng-live net://localhost|grep %s|cut -d' ' -f1",
				name);
	}
	if (ret < 0) {
		fprintf(stderr, "allocating cmd\n");
		goto end;
	}
	fprintf(stderr, "%s session started : ",
			(local) ? "Local" : "Live");
	ret = (system(cmd));
	if (ret != 0) {
		fprintf(stderr, "error: listing the sessions\n");
		ret = -1;
		goto end;
	}

end:
	return ret;
}

static
char *live_path(char *name)
{
	FILE *fp;
	int ret;
	char path[1035];
	char cmd[1024];
	char *out = NULL;

	ret = sprintf(cmd, "lttngtop -r net://localhost|grep %s|cut -d' ' -f1",
			name);
	if (ret < 0) {
		fprintf(stderr, "allocating cmd\n");
		goto end;
	}

	fp = popen(cmd, "r");
	if (fp == NULL) {
		printf("Failed to run command\n" );
		goto end;
	}

	/* Read the output a line at a time - output it. */
	out = fgets(path, sizeof(path)-1, fp);
	if (out)
		out = strdup(path);

	/* close */
	pclose(fp);

end:
	return out;
}

static
int destroy(char *name)
{
	int ret;
	int sudo = 0;
	char cmd[1024];

	ret = system("groups|grep tracing >/dev/null");
	if (ret != 0 && getuid() != 0) {
		ret = system("sudo -l lttng >/dev/null");
		if (ret < 0) {
			fprintf(stderr, "[error] You are not root and not "
					"allowed by sudo to use lttng\n");
			ret = -1;
			goto end;
		}
		sudo = 1;
	}

	ret = sprintf(cmd, "%s lttng destroy %s >/dev/null",
			(sudo) ? "sudo" : " ", name);
	if (ret < 0) {
		fprintf(stderr, "allocating cmd\n");
		goto end;
	}

	ret = (system(cmd));
	if (ret != 0) {
		fprintf(stderr, "error: destroying the session %s\n", name);
		ret = -1;
		goto end;
	}

end:
	return ret;
}

int create_local_session()
{
	int ret;
	char *name;
	int sudo = 0;

	ret = check_requirements(&sudo);

	name = random_session_name();
	if (!name) {
		ret = -1;
		goto end;
	}

	ret = check_session_name(name, sudo);
	if (ret < 0) {
		goto end_free;
	}

	ret = local_session(name, sudo);
	if (ret < 0) {
		goto end_free;
	}

	ret = enable_events(name, sudo);
	if (ret < 0) {
		goto end_free;
	}

	ret = add_contexts(name, sudo);
	if (ret < 0) {
		goto end_free;
	}

	ret = start(name, sudo, 1, 1);
	if (ret < 0) {
		goto end_free;
	}

end_free:
	free(name);
end:
	return ret;
}

int destroy_live_local_session(char *name)
{
	return destroy(name);
}

int create_live_local_session(char **session_path, char **session_name, int print)
{
	int ret;
	char *name;
	int sudo = 0;

	ret = check_requirements(&sudo);

	name = random_session_name();
	if (!name) {
		ret = -1;
		goto end;
	}

	ret = check_session_name(name, sudo);
	if (ret < 0) {
		goto end_free;
	}

	ret = live_local_session(name, sudo);
	if (ret < 0) {
		goto end_free;
	}

	ret = enable_events(name, sudo);
	if (ret < 0) {
		goto end_free;
	}

	ret = add_contexts(name, sudo);
	if (ret < 0) {
		goto end_free;
	}

	ret = start(name, sudo, 0, print);
	if (ret < 0) {
		goto end_free;
	}

	if (session_path)
		*session_path = live_path(name);
	if (session_name) {
		*session_name = name;
		goto end;
	}

end_free:
	free(name);
end:
	return ret;
}

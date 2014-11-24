/*
 * vpnd - vpn manages daemon
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <stdlib.h>
#include <unistd.h>
#include "utils.h"
#include "cmd.h"

static struct runqueue q;


static void
command_run(struct runqueue *q, struct runqueue_task *t)
{
    struct command *cmd = container_of(t, struct command, proc.task);
    
    pid_t pid;

    pid = fork();
    if (pid < 0)
        return;

    if (pid) {
        runqueue_process_add(q, &cmd->proc, pid);
        return;
    }

    if (cmd->argc > 0) {
        char tmp[1024] = {0};
        char *cur = NULL;
        int i = 0, len = 0;
        cur = tmp;
        for (i=0; i<cmd->argc; i++) {
            len += sprintf(cur+len, "%s ", cmd->argv[i]);
        }
        LOG(L_DEBUG, "Fork pid(%d), cmd: %s", getpid(), tmp);

        execvp(cmd->argv[0], &cmd->argv[0]);
    }
    
    exit(1);
}

static void
command_complete(struct runqueue *q, struct runqueue_task *t)
{
    struct command *cmd = container_of(t, struct command, proc.task);
    for (int i=0; i<cmd->argc; ++i)
        free(cmd->argv[i]);
    free(cmd->argv);
    free(cmd);
    LOG(L_DEBUG, "pid(%d) command complete, free OK!!", cmd->proc.proc.pid);
}

void
add_command(int argc, ...)
{
    static const struct runqueue_task_type cmd_type = {
        .run = command_run,
        .cancel = runqueue_process_cancel_cb,
        .kill = runqueue_process_kill_cb,
    };
    struct command *cmd;

    cmd = calloc(1, sizeof(*cmd));
    cmd->proc.task.type = &cmd_type;
    cmd->proc.task.complete = command_complete;
    cmd->proc.task.run_timeout = 1000;
    cmd->argc = argc;
    cmd->argv = calloc(1, sizeof(char*) * (cmd->argc + 1));

    va_list ap;
    char *cur;
    int i;
    va_start(ap, argc);
    for (i=0; i<cmd->argc; ++i) {
        cur = (char*)va_arg(ap, char*);
        cmd->argv[i] = calloc(1, strlen(cur) + 1);
        strcpy(cmd->argv[i], cur);
    }
    cmd->argv[i] = NULL;
    va_end(ap);

    runqueue_task_add(&q, &cmd->proc.task, false);
}

static void
q_empty(struct runqueue *q)
{
}

static void __init
command_init(void)
{
    runqueue_init(&q);
    q.empty_cb = q_empty;
    q.max_running_tasks = 1;
}

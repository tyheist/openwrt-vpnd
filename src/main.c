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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <stdbool.h>
#include <signal.h>
#include <getopt.h>
#include <syslog.h>
#include "utils.h"
#include "ubus.h"
#include "config.h"

static bool use_syslog = true;

#define DEFAULT_CONFIG_PATH NULL
#define DEFAULT_IPSEC_PATH  "/etc/ipsec/"
#define DEFAULT_LOG_LEVEL L_NOTICE

const char *config_path = DEFAULT_CONFIG_PATH;
const char *ipsec_path = DEFAULT_IPSEC_PATH;
static char **global_argv;

static int log_level = DEFAULT_LOG_LEVEL;
static const int log_class[] = {
    [L_CRIT] = LOG_CRIT,
    [L_WARNING] = LOG_WARNING,
    [L_NOTICE] = LOG_NOTICE,
    [L_INFO] = LOG_INFO,
    [L_DEBUG] = LOG_DEBUG
};

void
vpnd_log_message(int priority, const char *fmt, ...)
{
    va_list vl;
    if (priority > log_level)
        return;

    va_start(vl, fmt);
    if (use_syslog) {
        vsyslog(log_class[priority], fmt, vl);
    } else {
        vfprintf(stderr, fmt, vl);
    }
    va_end(vl);
}

static int
usage(const char *progname)
{
    fprintf(stderr, "Usage: %s [options]\n"
            "Options:\n"
            " -s <path>:         Path to the ubus socket\n"
            " -i <path>:         Path to openswan configure\n"
            "                      (default: "DEFAULT_IPSEC_PATH")\n"
            " -l <level>:        Log output level (0-4)\n"
            "                      (default: %d)\n"
            "\n", progname, DEFAULT_LOG_LEVEL);
    return 0;
}

static void
vpnd_handle_signal(int signo)
{
    uloop_end();
}

static void
vpnd_setup_signals(void)
{
    struct sigaction s;

    memset(&s, 0, sizeof(s));
    s.sa_handler = vpnd_handle_signal;
    s.sa_flags = 0;
    sigaction(SIGINT, &s, NULL);
    sigaction(SIGTERM, &s, NULL);
    sigaction(SIGUSR1, &s, NULL);
    sigaction(SIGUSR2, &s, NULL);

    s.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &s, NULL);
}

int
main(int argc, char **argv)
{
    const char *socket = NULL;
    int ch;

    global_argv = argv;

    while ((ch = getopt(argc, argv, "s:i:l:")) != -1) {
        switch (ch) {
            case 's':
                socket = optarg;
                break;
            case 'i':
                ipsec_path = optarg;
                break;
            case 'l':
                log_level = atoi(optarg);
                if (log_level >= ARRAY_SIZE(log_class))
                    log_level = ARRAY_SIZE(log_class) - 1;
                break;
            default:
                return usage(argv[0]);
        }
    }

    if (use_syslog)
        openlog("VPND", 0, LOG_DAEMON);

    vpnd_setup_signals();

    if (vpnd_ubus_init(socket) < 0) {
        fprintf(stderr, "Failed to connect to ubusd\n");
        return 1;
    }

    config_init_all();

    uloop_run();

    vpnd_ubus_done();

    LOG(L_NOTICE, "GOING TO EXIT!!!!");
    if (use_syslog)
        closelog();

    return 0;
}

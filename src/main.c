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
#include <stdarg.h>
#include <syslog.h>
#include <stdbool.h>
#include "utils.h"

static bool use_syslog = true;

#define DEFAULT_CONFIG_PATH NULL
const char *config_path = DEFAULT_CONFIG_PATH;

#define DEFAULT_LOG_LEVEL L_NOTICE
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

int
main(int argc, char **argv)
{
    return 0;
}

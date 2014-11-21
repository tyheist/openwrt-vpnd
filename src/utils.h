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

#ifndef __VPND_UTILS_H__
#define __VPND_UTILS_H__

#include <unistd.h>
#include <stdio.h>
#include <uci_blob.h>
#include <libubox/list.h>
#include <libubox/avl.h>
#include <libubox/avl-cmp.h>
#include <libubox/blobmsg.h>
#include <libubox/vlist.h>
#include <libubox/utils.h>
#include <libubox/uloop.h>
#include <uci.h>

extern const char *config_path;
extern const char *ipsec_path;
extern bool dump;

#define __init __attribute__((constructor))


enum {
    L_CRIT,
    L_WARNING,
    L_NOTICE,
    L_INFO,
    L_DEBUG
};

void vpnd_log_message(int priority, const char *fmt, ...);
#ifdef DEBUG
    #define LOG(prio, fmt, ...) vpnd_log_message(prio, "%s(%d): " fmt "\n", __func__, __LINE__, ## __VA_ARGS__);
#else
    #define LOG(prio, fmt, ...) no_debug(fmt, ## __VA_AGRS__); 
#endif

static inline void no_debug(const char *fmt, ...)
{
}

static inline void system_fd_set_cloexec(int fd)
{
#ifdef FD_CLOEXEC
    fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
#endif
}

static inline int run_cmd(const char *cmd)
{
    if (dump) {
        LOG(L_DEBUG, "%s", cmd);
    } else {
        return system(cmd);
    }
    return 0;
}

#endif /** __VPND_UTILS_H__ */


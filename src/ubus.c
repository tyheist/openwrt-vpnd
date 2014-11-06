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

#include <libubox/list.h>
#include <libubus.h>
#include "utils.h"
#include "ubus.h"

static struct list_head h_ubus_obj = LIST_HEAD_INIT(h_ubus_obj);
struct ubus_context *ubus_ctx = NULL;
static const char *ubus_path;

/**
 * ----------------------------------------
 *  ubus type routine
 * ----------------------------------------
 */
void
vpn_ubus_add_dynamic_object(struct vpn *vpn)
{
    struct ubus_object *obj = &vpn->obj;
    int ret = 0;
    char *name = NULL;

    ret = ubus_add_object(ubus_ctx, &vpn->obj);
    if (ret != 0) {
        LOG(L_WARNING, "failed to publish dynamic ubus object '%s': %s", 
                vpn->obj.name, ubus_strerror(ret));
        name = (char*)obj->name;
        if (name) { free(name); obj->name = NULL; }
    }
}

void
vpn_ubus_add_static_object(struct ubus_object *obj)
{
    int ret = ubus_add_object(ubus_ctx, obj);
    if (ret != 0) {
        LOG(L_WARNING, "failed to publish static ubus object '%s': %s", 
                obj->name, ubus_strerror(ret));
        return;
    }
}

void
vpn_ubus_obj_register(struct vpn_ubus_obj *obj)
{
    list_add(&obj->list, &h_ubus_obj);
}

void
vpn_ubus_obj_unregister(struct vpn_ubus_obj *obj)
{
    list_del(&obj->list);
}

struct vpn_ubus_obj *
vpn_ubus_obj_lookup(const char *path)
{
    struct vpn_ubus_obj *obj;
    list_for_each_entry(obj, &h_ubus_obj, list) {
        if (!strcmp(obj->name, path))
            return obj;
    }
    return NULL;
}


/** 
 * ----------------------------------------
 * main ubus routine 
 * ----------------------------------------
 */
static void
vpnd_ubus_add_fd(void)
{
    ubus_add_uloop(ubus_ctx);
    system_fd_set_cloexec(ubus_ctx->sock.fd);
}

static void
vpnd_ubus_reconnect_timer(struct uloop_timeout *timeout)
{
    static struct uloop_timeout retry = {
        .cb = vpnd_ubus_reconnect_timer,
    };
    int t = 2;

    if (ubus_reconnect(ubus_ctx, ubus_path) != 0) {
        LOG(L_WARNING, "failed to reconnect ubusd, trying again in %d seconds", t);
        uloop_timeout_set(&retry, t * 1000);
        return;
    }

    LOG(L_NOTICE, "reconnected to ubusd, new id: %08x", ubus_ctx->local_id);
    vpnd_ubus_add_fd();
}

static void
vpnd_ubus_connection_lost(struct ubus_context *ctx)
{
    vpnd_ubus_reconnect_timer(NULL);
}

int
vpnd_ubus_init(const char *path)
{
    uloop_init();
    ubus_path = path;

    ubus_ctx = ubus_connect(path);
    if (!ubus_ctx)
        return -EIO;

    LOG(L_NOTICE, "connected ubusd as %08x", ubus_ctx->local_id);
    ubus_ctx->connection_lost = vpnd_ubus_connection_lost;
    vpnd_ubus_add_fd();

    struct vpn_ubus_obj *obj;
    list_for_each_entry(obj, &h_ubus_obj, list) {
        if (obj->init) {
            vpn_ubus_add_static_object(obj->ubus);
        }
    }

    LOG(L_DEBUG, "vpnd init ubus OK");
    return 0;
}

void
vpnd_ubus_done(void)
{
    ubus_free(ubus_ctx);
}


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

#ifndef __VPND_VPN_H__
#define __VPND_VPN_H__

#include <libubox/list.h>
#include <libubox/vlist.h>
#include <libubox/blobmsg.h>
#include <libubus.h>
#include "utils.h"

extern struct vlist_tree h_vpns;
struct vpn;
struct vpn_type;
struct vpn_ops;

enum vpn_kind {
    VPN_KIND_NULL = 0,
    VPN_KIND_IPSEC,
    VPN_KIND_L2TP,
    VPN_KIND_PPTP,
    __VPN_KIND_MAX
};

struct vpn_ubus_obj {
    struct list_head list;
    const char *name;
    struct ubus_object *ubus;
    bool init;
    bool dyna;
};

struct vpn_ops {
    int (*prepare)(struct vpn *);
    int (*config)(struct vpn *);
    int (*setup)(struct vpn *);
    int (*up)(struct vpn *);
    int (*down)(struct vpn *);
    int (*finish)(struct vpn *);
    int (*dump_info)(struct vpn *);
};

struct vpn_type {
    struct list_head list;
    const char *name;
    const struct uci_blob_param_list *config_params;

    struct vpn *(*create)(struct vpn *vpn, struct blob_attr *config);
    void (*free)(struct vpn *vpn);
    void (*update)(struct vpn *new, struct vpn *old);

    struct vpn_ops *ops;
};

struct vpn {
    struct vlist_node node;
    enum vpn_kind kind;
    char *name;                     /** avl key word */
    const struct vpn_type *type;
    struct ubus_object obj;
    struct blob_attr *config;

    void *seting;
    void *status;

    bool config_pending;            /** vpn_type->ops->config done */
    bool available;                 /** object enable or not */

    char *uci_p;
    char *uci_s;
};


void vpn_type_register(struct vpn_type *type);
void vpn_type_unregister(struct vpn_type *type);
struct vpn_type *vpn_type_lookup(const char *name);

struct vpn *vpn_alloc(const char *name, enum vpn_kind kind, const struct vpn_type *type, 
        struct vpn_ubus_obj *obj, struct blob_attr *config, 
        const char *uci_p, const char *uci_s);
void vpn_free(struct vpn *vpn);
void vpn_setup(const char *name, enum vpn_kind kind, const struct vpn_type *type, 
        struct vpn_ubus_obj *obj, struct blob_attr *config, 
        const char *uci_p, const char *uci_s);
#endif /** __VPND_VPN_H__ */


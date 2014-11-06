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

#define _GNU_SOURCE

#include <stdio.h>
#include "utils.h"
#include "vpn.h"
#include "ubus.h"


static struct list_head h_vpn_type = LIST_HEAD_INIT(h_vpn_type);
struct vlist_tree h_vpns;

struct vpn *
vpn_alloc(const char *name, enum vpn_kind kind, const struct vpn_type *type, 
        struct vpn_ubus_obj *obj, struct blob_attr *config, 
        const char *uci_p, const char *uci_s)
{
    struct vpn *vpn = NULL;
    char *vpn_name=NULL, *uci_pname=NULL, *uci_sname=NULL, *vpn_obj=NULL;

    vpn = calloc_a(sizeof(*vpn), &vpn_name, strlen(name)+1, 
            &uci_pname, strlen(uci_p)+1, &uci_sname, strlen(uci_s)+1);

    if (!vpn) {
        LOG(L_WARNING, "alloc vpn object error");
        goto error;
    }

    vpn->name   = strcpy(vpn_name, name);
    vpn->uci_p  = strcpy(uci_pname, uci_p);
    vpn->uci_s  = strcpy(uci_sname, uci_s);
    vpn->kind   = kind;
    vpn->config = config;
    vpn->type   = type;
    vpn->config_pending = true;

    /** ubus object init */
    asprintf(&vpn_obj, "%s.%s", obj->name, name);
    vpn->obj.name = vpn_obj;
    vpn->obj.type = obj->ubus->type;
    vpn->obj.methods = obj->ubus->methods;
    vpn->obj.n_methods = obj->ubus->n_methods;

    /** create assign vpn type */
    if (vpn->type->create) {
        if (!vpn->type->create(vpn, config)) {
            LOG(L_WARNING, "alloc vpn type '%s' object error", type->name);
            goto error;
        }
    }

    return vpn;
error:
    return NULL;
}

void
vpn_free(struct vpn *vpn)
{
    if (!vpn)
        return;

    if (vpn->type->free) {
        vpn->type->free(vpn);
    }

    free(vpn);
    vpn = NULL;
}

void
vpn_setup(const char *name, enum vpn_kind kind, const struct vpn_type *type, 
        struct vpn_ubus_obj *obj, struct blob_attr *config, 
        const char *uci_p, const char *uci_s)
{
    struct vpn *vpn = NULL;

    vpn = vpn_alloc(name, kind, type, obj, config, uci_p, uci_s);
    if (!vpn) {
        goto error;
    }

    vlist_add(&h_vpns, &vpn->node, vpn->name);
    vpn = vlist_find(&h_vpns, vpn->name, vpn, node);
    if (!vpn) {
        LOG(L_WARNING, "find vpn object (%s) error", vpn->name);
        goto error;
    }

    type->ops->config(vpn);
    type->ops->setup(vpn);
    if (type->ops->prepare) { type->ops->prepare(vpn); }
    type->ops->up(vpn);
    if (type->ops->finish) { type->ops->finish(vpn); }

    return;
error:
    vpn_free(vpn);
}

void
vpn_type_register(struct vpn_type *type)
{
    list_add(&type->list, &h_vpn_type);
}

void
vpn_type_unregister(struct vpn_type *type)
{
    list_del(&type->list);
}

struct vpn_type *
vpn_type_lookup(const char *name)
{
    struct vpn_type *t;
    list_for_each_entry(t, &h_vpn_type, list) {
        if (!strcmp(t->name, name))
            return t;
    }
    return NULL;
}


static void
vpn_update(struct vlist_tree *tree, struct vlist_node *node_new, struct vlist_node *node_old)
{
    struct vpn *vpn_old = container_of(node_old, struct vpn, node);
    struct vpn *vpn_new = container_of(node_new, struct vpn, node);

    if (node_old && node_new) {
        vpn_old->type->update(vpn_new, vpn_old);
    } else if (node_old) {
        vpn_old->type->update(NULL, vpn_old);
    } else if (node_new) {
        vpn_new->type->update(vpn_new, NULL);
        vpn_ubus_add_dynamic_object(vpn_new);
    }
}

static void __init
vpn_init_list(void)
{
    vlist_init(&h_vpns, avl_strcmp, vpn_update);
    h_vpns.keep_old = true;
    h_vpns.no_delete = true;
}


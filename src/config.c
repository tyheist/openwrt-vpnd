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
#include "utils.h"
#include "vpn.h"
#include "config.h"
#include "ubus.h"

static struct list_head h_vpn_uci_package = LIST_HEAD_INIT(h_vpn_uci_package);
static struct blob_buf b;

void
config_init_section(const char *name, enum vpn_kind kind, const char *vpn_type, struct vpn_uci_section *s)
{
    struct vpn_type *type = NULL;
    struct vpn_ubus_obj *obj = NULL;
    struct blob_attr *config =NULL;
    struct vpn_uci_package *p = NULL;
    char *path= NULL;

    type = vpn_type_lookup(vpn_type);
    if (!type) {
        LOG(L_WARNING, "vpn type %s not exist!", vpn_type);
        goto error;
    }

    p = container_of(s, struct vpn_uci_package, sections);
    if (asprintf(&path, "%s.%s", p->name, s->name) == -1)
        goto error;

    obj = vpn_ubus_obj_lookup(path);
    if (!obj) {
        LOG(L_WARNING, "vpn ubus object %s not exist!", path);
        goto error;
    }

    blob_buf_init(&b, 0);
    uci_to_blob(&b, s->uci_section, type->config_params);
    config = blob_memdup(b.head);
    if (!config) {
        LOG(L_WARNING, "dup blob %s uci error", name);
        goto error;
    }
    
    vpn_setup(name, kind, type, obj, config, p->name, s->name);
error:
    if (path) { free(path); path = NULL; }
}

void
vpn_uci_package_register(struct vpn_uci_package *p)
{
    list_add(&p->list, &h_vpn_uci_package);
}

void
vpn_uci_package_unregister(struct vpn_uci_package *p)
{
    list_del(&p->list);
}

static void
config_init_package(struct vpn_uci_package *u)
{
    struct uci_context *ctx = u->uci_ctx;
    struct uci_package *p = NULL;
    int i = 0;

    if (!ctx) {
        ctx = uci_alloc_context();
        u->uci_ctx = ctx;

        ctx->flags &= ~UCI_FLAG_STRICT;
        if (config_path)
            uci_set_confdir(ctx, config_path);
    } else {
        p = uci_lookup_package(ctx, u->name);
        if (p)
            uci_unload(ctx, p);
    }

    if (uci_load(ctx, u->name, &p))
        u->uci_package = NULL;
    else
        u->uci_package = p;

    if (!u->uci_package) {
        LOG(L_NOTICE, "Failed to load uci '%s' config", u->name);
        return;
    }

    struct uci_element *e;
    uci_foreach_element(&u->uci_package->sections, e) {
        struct uci_section *s = uci_to_section(e);
        for (i=0; i<u->n_sections; ++i) {
            if (!strcmp(u->sections[i].name, s->type)) {
                u->sections[i].uci_ctx = u->uci_ctx;
                u->sections[i].uci_section = s;
                u->sections[i].init(&u->sections[i]);
            }
        }
    }
}

void
config_init_all(void)
{
    struct vpn_uci_package *p;
    list_for_each_entry(p, &h_vpn_uci_package , list) {
        config_init_package(p);
    }
}


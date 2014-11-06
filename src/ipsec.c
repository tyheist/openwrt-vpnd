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

#include "utils.h"
#include "vpn.h"
#include "config.h"
#include "ubus.h"

static struct blob_buf b;

struct ipsec_policy_seting {
    struct blob_attr *left,
                     *right,
                     *leftsubnet,
                     *rightsubnet,
                     *leftsubnets,
                     *rightsubnets,
                     *type,
                     *authby,
                     *ike,
                     *esp,
                     *leftid,
                     *rightid,
                     *_auto,
                     *aggrmode,
                     *ikelifetime,
                     *keylife;
};

enum ipsec_tunnel_stat {
    IPSEC_TUNNEL_UP,
    IPSEC_TUNNEL_DOWN,
};

struct ipsec_tunnel_status {
    struct vlist_node node;
    struct blob_buf right;
    enum ipsec_tunnel_stat status;
};
struct ipsec_policy_status {
    struct vlist_tree status;
    bool up;
};

enum {
    IPSEC_POLICY_ATTR_NAME,
    IPSEC_POLICY_ATTR_LEFT,
    IPSEC_POLICY_ATTR_RIGHT,
    IPSEC_POLICY_ATTR_LEFTSUBNET,
    IPSEC_POLICY_ATTR_RIGHTSUBNET,
    IPSEC_POLICY_ATTR_LEFTSUBNETS,
    IPSEC_POLICY_ATTR_RIGHTSUBNETS,
    IPSEC_POLICY_ATTR_TYPE,
    IPSEC_POLICY_ATTR_AUTHBY,
    IPSEC_POLICY_ATTR_IKE,
    IPSEC_POLICY_ATTR_ESP,
    IPSEC_POLICY_ATTR_LEFTID,
    IPSEC_POLICY_ATTR_RIGHTID,
    IPSEC_POLICY_ATTR_AUTO,
    IPSEC_POLICY_ATTR_AGGRMODE,
    IPSEC_POLICY_ATTR_IKELIFETIME,
    IPSEC_POLICY_ATTR_KEYLIFE,
    __IPSEC_POLICY_ATTR_MAX
};

static const struct blobmsg_policy ipsec_policy_attrs[__IPSEC_POLICY_ATTR_MAX] = {
    [IPSEC_POLICY_ATTR_NAME] = { .name = "name", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_POLICY_ATTR_LEFT] = { .name = "left", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_POLICY_ATTR_RIGHT] = { .name = "right", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_POLICY_ATTR_LEFTSUBNET] = { .name = "leftsubnet", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_POLICY_ATTR_RIGHTSUBNET] = { .name = "rightsubnet", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_POLICY_ATTR_LEFTSUBNETS] = { .name = "leftsubnets", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_POLICY_ATTR_RIGHTSUBNETS] = { .name = "rightsubnets", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_POLICY_ATTR_TYPE] = { .name = "type", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_POLICY_ATTR_AUTHBY] = { .name = "authby", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_POLICY_ATTR_IKE] = { .name = "ike", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_POLICY_ATTR_ESP] = { .name = "esp", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_POLICY_ATTR_LEFTID] = { .name = "leftid", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_POLICY_ATTR_RIGHTID] = { .name = "rightd", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_POLICY_ATTR_AUTO] = { .name = "auto", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_POLICY_ATTR_AGGRMODE] = { .name = "aggrmode", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_POLICY_ATTR_IKELIFETIME] = { .name = "ikelifetime", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_POLICY_ATTR_KEYLIFE] = { .name = "keylife", .type = BLOBMSG_TYPE_STRING },
};

/*
 *static const struct uci_blob_param_info ipsec_policy_attr_info[__IPSEC_POLICY_ATTR_MAX] = {
 *    [IPSEC_POLICY_ATTR_NAME] = { .type = BLOBMSG_TYPE_STRING },
 *};
 */

static void
ipsec_policy_config_set(struct ipsec_policy_seting *seting, struct blob_attr *config)
{
    struct blob_attr *tb[__IPSEC_POLICY_ATTR_MAX];

    blobmsg_parse(ipsec_policy_attrs, __IPSEC_POLICY_ATTR_MAX, tb,
            blob_data(config), blob_len(config));

#define FIELD_SET(field, attr) \
    if (tb[attr]) { seting->field = tb[attr]; }

    FIELD_SET(left, IPSEC_POLICY_ATTR_LEFT);
    FIELD_SET(right, IPSEC_POLICY_ATTR_RIGHT);
    FIELD_SET(leftsubnet, IPSEC_POLICY_ATTR_LEFTSUBNET);
    FIELD_SET(rightsubnet, IPSEC_POLICY_ATTR_RIGHTSUBNET);
    FIELD_SET(leftsubnets, IPSEC_POLICY_ATTR_LEFTSUBNETS);
    FIELD_SET(rightsubnets, IPSEC_POLICY_ATTR_RIGHTSUBNETS);
    FIELD_SET(type, IPSEC_POLICY_ATTR_TYPE);
    FIELD_SET(authby, IPSEC_POLICY_ATTR_AUTHBY);
    FIELD_SET(ike, IPSEC_POLICY_ATTR_IKE);
    FIELD_SET(esp, IPSEC_POLICY_ATTR_ESP);
    FIELD_SET(leftid, IPSEC_POLICY_ATTR_LEFTID);
    FIELD_SET(rightid, IPSEC_POLICY_ATTR_RIGHTID);
    FIELD_SET(_auto, IPSEC_POLICY_ATTR_AUTO);
    FIELD_SET(aggrmode, IPSEC_POLICY_ATTR_AGGRMODE);
    FIELD_SET(ikelifetime, IPSEC_POLICY_ATTR_IKELIFETIME);
    FIELD_SET(keylife, IPSEC_POLICY_ATTR_KEYLIFE);
#undef FIELD_SET
}

static void
ipsec_policy_status_update(struct vlist_tree *tree, 
        struct vlist_node *node_new, struct vlist_node *node_old)
{
    return;
}

static struct vpn *
ipsec_policy_create(struct vpn *vpn, struct blob_attr *config)
{
    struct ipsec_policy_seting *seting = NULL;
    struct ipsec_policy_status *status = NULL;

    seting = calloc(1, sizeof(struct ipsec_policy_seting));
    if (!seting) {
        LOG(L_WARNING, "calloc ipsec policy seting error");
        goto error;
    }

    status = calloc(1, sizeof(struct ipsec_policy_status));
    if (!status) {
        LOG(L_WARNING, "calloc ipsec policy status error");
        goto error;
    }

    /** config */
    ipsec_policy_config_set(seting, config);

    /** status */
    vlist_init(&status->status, avl_strcmp, ipsec_policy_status_update);

    vpn->seting = seting;
    vpn->status = status;

    return vpn;
error:
    if (!seting) { free(seting); seting = NULL; }
    if (!status) { free(status); status = NULL; }
    return NULL;
}

static void
ipsec_policy_free(struct vpn *vpn)
{
    if (vpn->seting) { 
        free(vpn->seting); 
        vpn->seting = NULL; 
    }

    if (vpn->status) {
        struct ipsec_policy_status *status = (struct ipsec_policy_status *)vpn->status;
        vlist_flush_all(&status->status);
        free(vpn->status);
        vpn->status = NULL;
    }
}

static void
ipsec_policy_change_config(struct vpn *new, struct vpn *old)
{
    struct blob_attr *old_config = old->config;
    struct ipsec_policy_seting *new_seting, *old_seting;
    bool reload = false;

    new_seting = (struct ipsec_policy_seting *)new->seting;
    old_seting = (struct ipsec_policy_seting *)old->seting;
#define CONFIG_CMP(field) \
    if (!blob_attr_equal(new_seting->field, old_seting->field)) { \
        LOG(L_DEBUG, "ipsec policy '%s' option '%s' change", new->name, #field); \
        reload = true; \
    }

    CONFIG_CMP(left);
    CONFIG_CMP(right);
    CONFIG_CMP(leftsubnet);
    CONFIG_CMP(rightsubnet);
    CONFIG_CMP(leftsubnets);
    CONFIG_CMP(rightsubnets);
    CONFIG_CMP(type);
    CONFIG_CMP(authby);
    CONFIG_CMP(ike);
    CONFIG_CMP(esp);
    CONFIG_CMP(leftid);
    CONFIG_CMP(rightid);
    CONFIG_CMP(_auto);
    CONFIG_CMP(aggrmode);
    CONFIG_CMP(ikelifetime);
    CONFIG_CMP(keylife);
#undef CONFIG_CMP

    if (reload) {
        old->config = new->config;
        new->config = NULL;
        free(old_config);

        /** reload config */
        ipsec_policy_config_set(old->seting, old->config);
        old->config_pending = true;
    }

    vpn_free(new);
}

/**
 * ---------------------------------------------------
 *  ipsec policy type routine
 * ---------------------------------------------------
 */
static void
ipsec_policy_update(struct vpn *new, struct vpn *old)
{
    if (new && old) {
        LOG(L_NOTICE, "update ipsec policy '%s'", new->name);
        ipsec_policy_change_config(new, old);
    } else if (old) {
        LOG(L_NOTICE, "remove ipsec policy '%s'", old->name);
    } else if (new) {
        LOG(L_NOTICE, "create ipsec policy '%s'", new->name);
        /** do nothing */
    }
}

static int
ipsec_policy_prepare(struct vpn *vpn)
{
    return 0;
}

static int
ipsec_policy_config(struct vpn *vpn)
{
    struct ipsec_policy_seting *seting = (struct ipsec_policy_seting *)vpn->seting;
    char *path = alloca(strlen(ipsec_path) + strlen(vpn->name) + 1);
    FILE *f;
    if (!vpn->config_pending) {
        LOG(L_NOTICE, "ipsec policy '%s' config not pending", vpn->name);
        return 0;
    }

    f = fopen(path, "w");
    if (!f) {
        return errno;
    }

    fprintf(f, "conn %s\n", vpn->name);
#define WRITE_F(field) \
    if (seting->field) { \
        fprintf(f, "\t%s=%s", #field, blobmsg_get_string(seting->field)); \
    }

#define WRITE_F_X(field) \
    if (seting->_##field) { \
        fprintf(f, "\t%s=%s", #field, blobmsg_get_string(seting->_##field)); \
    }

    WRITE_F(left);
    WRITE_F(right);
    WRITE_F(leftsubnet);
    WRITE_F(rightsubnet);
    WRITE_F(leftsubnets);
    WRITE_F(rightsubnets);
    WRITE_F(type);
    WRITE_F(authby);
    WRITE_F(ike);
    WRITE_F(esp);
    WRITE_F(leftid);
    WRITE_F(rightid);
    WRITE_F(aggrmode);
    WRITE_F(ikelifetime);
    WRITE_F(keylife);

    WRITE_F_X(auto);
#undef WRITE_F
#undef WRITE_F_X

    vpn->config_pending = false;

    fclose(f);
    return 0;
}

static int
ipsec_policy_down(struct vpn *vpn)
{
    struct ipsec_policy_status *status = (struct ipsec_policy_status *)vpn->status;
    char cmd[64] = {0};
    sprintf(cmd, "ipsec auto --down %s &", vpn->name);
    system(cmd);
    status->up = false;
    vlist_flush_all(&status->status);
    return 0;
}

static int
ipsec_policy_up(struct vpn *vpn)
{
    struct ipsec_policy_status *status = (struct ipsec_policy_status *)vpn->status;
    if (status->up) {
        ipsec_policy_down(vpn);
    }
    char cmd[64] = {0};
    sprintf(cmd, "ipsec auto --up %s &", vpn->name);
    system(cmd);
    status->up = true;
    return 0;
}

static int
ipsec_policy_finish(struct vpn *vpn)
{
    return 0;
}

static int
ipsec_policy_dump_info(struct vpn *vpn)
{
    return 0;
}

static void
ipsec_policy_get_status(struct vpn *vpn)
{
    return;
}

static const struct uci_blob_param_list ipsec_policy_attr_list = {
    .n_params = __IPSEC_POLICY_ATTR_MAX,
    .params = ipsec_policy_attrs,
    /*.info = ipsec_policy_attr_info,*/
};

static struct vpn_ops ipsec_policy_ops = {
    .prepare = ipsec_policy_prepare,
    .config = ipsec_policy_config,
    .up = ipsec_policy_up,
    .down = ipsec_policy_down,
    .finish = ipsec_policy_finish,
    .dump_info = ipsec_policy_dump_info,
};

static struct vpn_type ipsec_policy_type = {
    .name = "ipsec_policy",
    .config_params = &ipsec_policy_attr_list,
    .create = ipsec_policy_create,
    .free = ipsec_policy_free,
    .update = ipsec_policy_update,
    .ops = &ipsec_policy_ops,
};

/** uci config */
static void ipsec_policy_uci_section_handler(struct vpn_uci_section *s)
{
    const char *name = NULL;
    name = uci_lookup_option_string(s->uci_ctx, s->uci_section, "name");
    config_init_section(name, VPN_KIND_IPSEC, "ipsec_policy", s);
}

static struct vpn_uci_section ipsec_policy_uci_sections[] = {
    { .name = "policy", .init = ipsec_policy_uci_section_handler, },
};

static struct vpn_uci_package ipsec_uci = {
    .name= "ipsec",
    .sections = ipsec_policy_uci_sections,
    .n_sections = ARRAY_SIZE(ipsec_policy_uci_sections),
};

/** ipsec policy ubus object */
static int
ipsec_policy_ubus_up(struct ubus_context *ctx, struct ubus_object *obj,
        struct ubus_request_data *req, const char *method,
        struct blob_attr *msg)
{
    struct vpn *vpn;
    vpn = container_of(obj, struct vpn, obj);
    ipsec_policy_up(vpn);
    return 0;
}

static int
ipsec_policy_ubus_down(struct ubus_context *ctx, struct ubus_object *obj,
        struct ubus_request_data *req, const char *method,
        struct blob_attr *msg)
{
    struct vpn *vpn;
    vpn = container_of(obj, struct vpn, obj);
    ipsec_policy_down(vpn);
    return 0;
}

static int
ipsec_policy_ubus_get_status(struct ubus_context *ctx, struct ubus_object *obj,
        struct ubus_request_data *req, const char *method,
        struct blob_attr *msg)
{
    blob_buf_init(&b, 0);
    void *a = blobmsg_open_array(&b, "ipsec");

    struct vpn *vpn;
    vlist_for_each_element(&h_vpns, vpn, node) {
        if (vpn->kind == VPN_KIND_IPSEC) {
            void *i = blobmsg_open_table(&b, NULL);
            blobmsg_add_string(&b, "policy", vpn->name);
            ipsec_policy_get_status(vpn);
            blobmsg_close_table(&b, i);
        }
    }

    blobmsg_close_array(&b, a);
    ubus_send_reply(ctx, req, b.head);
    return 0;
}

static int
ipsec_policy_ubus_set_status(struct ubus_context *ctx, struct ubus_object *obj,
        struct ubus_request_data *req, const char *method,
        struct blob_attr *msg)
{
    return 0;
}

static struct ubus_method ipsec_policy_obj_methods[] = {
    { .name = "up", .handler = ipsec_policy_ubus_up },
    { .name = "down", .handler = ipsec_policy_ubus_down },
    { .name = "get_status", .handler = ipsec_policy_ubus_get_status },
    { .name = "set_status", .handler = ipsec_policy_ubus_set_status },
};

static struct ubus_object_type ipsec_policy_obj_type =
    UBUS_OBJECT_TYPE("ipsec_policy", ipsec_policy_obj_methods);

static struct ubus_object ipsec_policy_obj = {
    .name = "ipsec.policy",
    .type = &ipsec_policy_obj_type,
    .methods = ipsec_policy_obj_methods,
    .n_methods = ARRAY_SIZE(ipsec_policy_obj_methods),
};

static struct vpn_ubus_obj ipsec_ubus_policy_obj = {
    .name = "ipsec.policy",
    .ubus = &ipsec_policy_obj,
    .init = false,
};

/** ipsec main ubus object */
static int
ipsec_main_ubus_restart(struct ubus_context *ctx, struct ubus_object *obj,
        struct ubus_request_data *req, const char *mehtod,
        struct blob_attr *msg)
{
    LOG(L_DEBUG, "ipsec restart!!!!");
    return 0;
}

static int
ipsec_main_ubus_reload(struct ubus_context *ctx, struct ubus_object *obj,
        struct ubus_request_data *req, const char *mehtod,
        struct blob_attr *msg)
{
    LOG(L_DEBUG, "ipsec reload!!!!");
    return 0;
}

static struct ubus_method ipsec_main_obj_methods[] = {
    { .name = "restart", .handler = ipsec_main_ubus_restart },
    { .name = "reload", .handler = ipsec_main_ubus_reload },
};

static struct ubus_object_type ipsec_main_obj_type = 
    UBUS_OBJECT_TYPE("ipsec_main", ipsec_main_obj_methods);

static struct ubus_object ipsec_main_obj = {
    .name = "ipsec",
    .type = &ipsec_main_obj_type,
    .methods = ipsec_main_obj_methods,
    .n_methods = ARRAY_SIZE(ipsec_main_obj_methods),
};

static struct vpn_ubus_obj ipsec_ubus_main_obj = {
    .name = "ipsec",
    .ubus = &ipsec_main_obj,
    .init = true,
};

/** init */
static void __init 
ipsec_type_init(void)
{
    vpn_uci_package_register(&ipsec_uci);
    vpn_type_register(&ipsec_policy_type);
    vpn_ubus_obj_register(&ipsec_ubus_policy_obj);
    vpn_ubus_obj_register(&ipsec_ubus_main_obj);
}


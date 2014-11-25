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

#include <sys/stat.h>
#include <sys/types.h>
#include <libubox/blobmsg_json.h>
#include "utils.h"
#include "vpn.h"
#include "config.h"
#include "ubus.h"
#include "cmd.h"

static struct blob_buf b;

/**
 * ipsec policy seting object
 */
struct ipsec_policy_seting {
    char local[16];
    struct blob_attr *_enable;

    struct blob_attr *_left,
                     *_right,
                     *_leftsubnet,
                     *_rightsubnet,
                     /**_leftsubnets,*/
                     /**_rightsubnets,*/
                     *_type,
                     *_authby,
                     *_ike,
                     *_phase2alg,
                     *_phase2,
                     *_leftid,
                     *_rightid,
                     *_auto,
                     *_aggrmode,
                     *_ikelifetime,
                     *_keylife,
                     *_dpddelay,
                     *_dpdtimeout,
                     *_dpdaction,
                     *_psk;
};

enum ipsec_tunnel_stat {
    IPSEC_TUNNEL_UP,
    IPSEC_TUNNEL_DOWN,
    IPSEC_TUNNEL_P1_INIT,
    IPSEC_TUNNEL_P1_ENCRYPT,
    IPSEC_TUNNEL_P1_AUTH,
    IPSEC_TUNNEL_P1_UP,
    IPSEC_TUNNEL_P1_DOWN,
    IPSEC_TUNNEL_P2_NEG,
    IPSEC_TUNNEL_P2_UP,
    __IPSEC_TUNNEL_MAX
};

/**
 * ipsec policy status object
 */
struct ipsec_tunnel_status {
    struct vlist_node node;

    char *right;
    char *status;
    /*enum ipsec_tunnel_stat status;*/
};

struct ipsec_policy_status {
    struct vlist_tree status;
    bool up;
};

/*
 * ipsec setup seting object
 */
struct ipsec_setup_seting {
    struct blob_attr *_enable,
                     *_plutodebug;
};

struct ipsec_setup_status {
    bool running;
};

enum {
    IPSEC_POLICY_ATTR_NAME,
    IPSEC_POLICY_ATTR_LEFT,
    IPSEC_POLICY_ATTR_RIGHT,
    IPSEC_POLICY_ATTR_LEFTSUBNET,
    IPSEC_POLICY_ATTR_RIGHTSUBNET,
    /*IPSEC_POLICY_ATTR_LEFTSUBNETS,*/
    /*IPSEC_POLICY_ATTR_RIGHTSUBNETS,*/
    IPSEC_POLICY_ATTR_TYPE,
    IPSEC_POLICY_ATTR_AUTHBY,
    IPSEC_POLICY_ATTR_IKE,
    IPSEC_POLICY_ATTR_PHASE2ALG,
    IPSEC_POLICY_ATTR_PHASE2,
    IPSEC_POLICY_ATTR_LEFTID,
    IPSEC_POLICY_ATTR_RIGHTID,
    IPSEC_POLICY_ATTR_AUTO,
    IPSEC_POLICY_ATTR_AGGRMODE,
    IPSEC_POLICY_ATTR_IKELIFETIME,
    IPSEC_POLICY_ATTR_KEYLIFE,
    IPSEC_POLICY_ATTR_PSK,
    IPSEC_POLICY_ATTR_ENABLE,
    IPSEC_POLICY_ATTR_DPDDELAY,
    IPSEC_POLICY_ATTR_DPDTIMEOUT,
    IPSEC_POLICY_ATTR_DPDACTION,
    __IPSEC_POLICY_ATTR_MAX
};

/**
 * ipsec policy configure attr list
 */
static const struct blobmsg_policy ipsec_policy_attrs[__IPSEC_POLICY_ATTR_MAX] = {
    [IPSEC_POLICY_ATTR_NAME] = { .name = "name", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_POLICY_ATTR_LEFT] = { .name = "left", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_POLICY_ATTR_RIGHT] = { .name = "right", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_POLICY_ATTR_LEFTSUBNET] = { .name = "leftsubnet", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_POLICY_ATTR_RIGHTSUBNET] = { .name = "rightsubnet", .type = BLOBMSG_TYPE_STRING },
    /*[IPSEC_POLICY_ATTR_LEFTSUBNETS] = { .name = "leftsubnets", .type = BLOBMSG_TYPE_STRING },*/
    /*[IPSEC_POLICY_ATTR_RIGHTSUBNETS] = { .name = "rightsubnets", .type = BLOBMSG_TYPE_STRING },*/
    [IPSEC_POLICY_ATTR_TYPE] = { .name = "type", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_POLICY_ATTR_AUTHBY] = { .name = "authby", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_POLICY_ATTR_IKE] = { .name = "ike", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_POLICY_ATTR_PHASE2ALG] = { .name = "phase2alg", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_POLICY_ATTR_PHASE2] = { .name = "phase2", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_POLICY_ATTR_LEFTID] = { .name = "leftid", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_POLICY_ATTR_RIGHTID] = { .name = "rightid", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_POLICY_ATTR_AUTO] = { .name = "auto", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_POLICY_ATTR_AGGRMODE] = { .name = "aggrmode", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_POLICY_ATTR_IKELIFETIME] = { .name = "ikelifetime", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_POLICY_ATTR_KEYLIFE] = { .name = "keylife", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_POLICY_ATTR_PSK] = { .name = "psk", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_POLICY_ATTR_ENABLE] = { .name = "enable", .type = BLOBMSG_TYPE_BOOL },
    [IPSEC_POLICY_ATTR_DPDDELAY] = { .name = "dpddelay", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_POLICY_ATTR_DPDTIMEOUT] = { .name = "dpdtimeout", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_POLICY_ATTR_DPDACTION] = { .name = "dpdaction", .type = BLOBMSG_TYPE_STRING },
};

enum {
    IPSEC_SETUP_ATTR_ENABLE,
    IPSEC_SETUP_ATTR_PLUTODEBUG,
    __IPSEC_SETUP_ATTR_MAX
};

/**
 * ipsec setup configure attr list
 */
static const struct blobmsg_policy ipsec_setup_attrs[__IPSEC_SETUP_ATTR_MAX] = {
    [IPSEC_SETUP_ATTR_ENABLE] = { .name = "enable", .type = BLOBMSG_TYPE_BOOL },
    [IPSEC_SETUP_ATTR_PLUTODEBUG] = { .name = "plutodebug", .type = BLOBMSG_TYPE_STRING },
};

enum {
    IPSEC_STATUS_ATTR_RIGHT,
    IPSEC_STATUS_ATTR_STAT,
    __IPSEC_STATUS_ATTR_MAX
};

/**
 * ipsec tunnel status attr list
 */
static const struct blobmsg_policy ipsec_status_attrs[__IPSEC_STATUS_ATTR_MAX] = {
    [IPSEC_STATUS_ATTR_RIGHT] = { .name = "right", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_STATUS_ATTR_STAT] = { .name = "stat", .type = BLOBMSG_TYPE_STRING },
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
    if (tb[attr]) { seting->_##field = tb[attr]; } \
    else { seting->_##field = NULL; }

    FIELD_SET(left, IPSEC_POLICY_ATTR_LEFT);
    FIELD_SET(right, IPSEC_POLICY_ATTR_RIGHT);
    FIELD_SET(leftsubnet, IPSEC_POLICY_ATTR_LEFTSUBNET);
    FIELD_SET(rightsubnet, IPSEC_POLICY_ATTR_RIGHTSUBNET);
    /*FIELD_SET(leftsubnets, IPSEC_POLICY_ATTR_LEFTSUBNETS);*/
    /*FIELD_SET(rightsubnets, IPSEC_POLICY_ATTR_RIGHTSUBNETS);*/
    FIELD_SET(type, IPSEC_POLICY_ATTR_TYPE);
    FIELD_SET(authby, IPSEC_POLICY_ATTR_AUTHBY);
    FIELD_SET(ike, IPSEC_POLICY_ATTR_IKE);
    FIELD_SET(phase2alg, IPSEC_POLICY_ATTR_PHASE2ALG);
    FIELD_SET(phase2, IPSEC_POLICY_ATTR_PHASE2);
    FIELD_SET(leftid, IPSEC_POLICY_ATTR_LEFTID);
    FIELD_SET(rightid, IPSEC_POLICY_ATTR_RIGHTID);
    FIELD_SET(auto, IPSEC_POLICY_ATTR_AUTO);
    FIELD_SET(aggrmode, IPSEC_POLICY_ATTR_AGGRMODE);
    FIELD_SET(ikelifetime, IPSEC_POLICY_ATTR_IKELIFETIME);
    FIELD_SET(keylife, IPSEC_POLICY_ATTR_KEYLIFE);
    FIELD_SET(psk, IPSEC_POLICY_ATTR_PSK);
    FIELD_SET(dpddelay, IPSEC_POLICY_ATTR_DPDDELAY);
    FIELD_SET(dpdtimeout, IPSEC_POLICY_ATTR_DPDTIMEOUT);
    FIELD_SET(dpdaction, IPSEC_POLICY_ATTR_DPDACTION);

    FIELD_SET(enable, IPSEC_POLICY_ATTR_ENABLE);
#undef FIELD_SET
}

static void
ipsec_policy_status_update(struct vlist_tree *tree, 
        struct vlist_node *node_new, struct vlist_node *node_old)
{
    /*struct ipsec_tunnel_status *s_new = container_of(node_new, struct ipsec_tunnel_status, node);*/
    struct ipsec_tunnel_status *s_old = container_of(node_old, struct ipsec_tunnel_status, node);

    if (node_old) {
        if (s_old) {
            free(s_old);
            s_old = NULL;
        }
    }

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
    status->up = false;

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
    if (!blob_attr_equal(new_seting->_##field, old_seting->_##field)) { \
        LOG(L_DEBUG, "ipsec policy '%s' option '%s' change", new->name, #field); \
        reload = true; \
    }

    CONFIG_CMP(left);
    CONFIG_CMP(right);
    CONFIG_CMP(leftsubnet);
    CONFIG_CMP(rightsubnet);
    /*CONFIG_CMP(leftsubnets);*/
    /*CONFIG_CMP(rightsubnets);*/
    CONFIG_CMP(type);
    CONFIG_CMP(authby);
    CONFIG_CMP(ike);
    CONFIG_CMP(phase2alg);
    CONFIG_CMP(phase2);
    CONFIG_CMP(leftid);
    CONFIG_CMP(rightid);
    CONFIG_CMP(auto);
    CONFIG_CMP(aggrmode);
    CONFIG_CMP(ikelifetime);
    CONFIG_CMP(keylife);
    CONFIG_CMP(psk);
    CONFIG_CMP(dpddelay);
    CONFIG_CMP(dpdtimeout);
    CONFIG_CMP(dpdaction);

    CONFIG_CMP(enable);
#undef CONFIG_CMP

    if (reload) {
        old->config = new->config;
        new->config = NULL;
        free(old_config);

        /** reload config */
        ipsec_policy_config_set(old_seting, old->config);
        old->config_pending = true;
    }

    vpn_free(new);
}

static void
ipsec_policy_remove_config(struct vpn *vpn)
{
    vpn->type->ops->down(vpn);
    vpn->type->ops->disable(vpn);
    vpn_free(vpn);
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
        ipsec_policy_remove_config(old);
    } else if (new) {
        LOG(L_NOTICE, "create ipsec policy '%s'", new->name);
        /** do nothing */
    }
}

static int
ipsec_policy_prepare(struct vpn *vpn)
{
    LOG(L_DEBUG, "ipsec policy '%s' prepare", vpn->name);
    return 0;
}

static void
ipsec_policy_left_get_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    if (!msg)
        return;
    enum {
        ADDR_IPV4,
        __ADDR_MAX
    };
    static const struct blobmsg_policy policy[__ADDR_MAX] = {
        [ADDR_IPV4] = { "ipv4-address", BLOBMSG_TYPE_ARRAY },
    };
    struct blob_attr *tb[__ADDR_MAX];
    struct blob_attr *cur, *cur1;
    int rem, rem1;
    struct vpn *vpn = (struct vpn*)req->priv;
    struct ipsec_policy_seting *seting = (struct ipsec_policy_seting *)vpn->seting;

    blobmsg_parse(policy, __ADDR_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));
    if (tb[ADDR_IPV4]) {
        rem = blobmsg_data_len(tb[ADDR_IPV4]);
        __blob_for_each_attr(cur, blobmsg_data(tb[ADDR_IPV4]), rem) {
            rem1 = blobmsg_data_len(cur);
            __blob_for_each_attr(cur1, blobmsg_data(cur), rem1) {
                if (!strcmp(blobmsg_name(cur1), "address")) {
                    if (strcmp(blobmsg_get_string(cur1), seting->local)) {
                        memcpy(seting->local, blobmsg_get_string(cur1), sizeof(seting->local));
                        vpn->config_pending = true;
                    }
                    return;
                }
            }
        }
    }
}

static void 
ipsec_policy_left_get(struct vpn *vpn, char *net)
{
    uint32_t id;
    int ret;
    char path[64] = {0};

    sprintf(path, "network.interface.%s", net);
    ret = ubus_lookup_id(ubus_ctx, path, &id);
    if (ret) {
        LOG(L_WARNING, "ubus lookup object '%s' id failed", path);
        return;
    }

    ret = ubus_invoke(ubus_ctx, id, "status", NULL, ipsec_policy_left_get_cb, vpn, 500);
    if (ret != 0) {
        LOG(L_WARNING, "ubus invoke '%s status' failed", path);
        return;
    }
}

static int
ipsec_policy_config(struct vpn *vpn)
{
    LOG(L_DEBUG, "ipsec policy '%s' config", vpn->name);
    struct ipsec_policy_seting *seting = (struct ipsec_policy_seting *)vpn->seting;
    char *path = alloca(strlen(ipsec_path) + strlen(vpn->name) + 16);
    FILE *f;
    if (!vpn->config_pending) {
        LOG(L_NOTICE, "ipsec policy '%s' config not pending", vpn->name);
        return -1;
    }

    sprintf(path, "%s%s.conf", ipsec_path, vpn->name);
    f = fopen(path, "w");
    if (!f) {
        LOG(L_DEBUG, "Can not open file '%s'", path);
        return errno;
    }

    ipsec_policy_left_get(vpn, blobmsg_get_string(seting->_left));

    if (!blobmsg_get_bool(seting->_enable)) {
        fclose(f);
        vpn->type->ops->down(vpn);
        vpn->type->ops->disable(vpn);
        return -1;
    }

    fprintf(f, "conn %s\n", vpn->name);
    fprintf(f, "\t%s=%s\n", "left", seting->local);

#define WRITE_F(field) \
    if (seting->_##field) { \
        fprintf(f, "\t%s=%s\n", #field, blobmsg_get_string(seting->_##field)); \
    }

    /*WRITE_F(left);*/
    WRITE_F(right);
    WRITE_F(leftsubnet);
    WRITE_F(rightsubnet);
    /*WRITE_F(leftsubnets);*/
    /*WRITE_F(rightsubnets);*/
    WRITE_F(type);
    WRITE_F(authby);
    WRITE_F(ike);
    WRITE_F(phase2alg);
    WRITE_F(phase2);
    WRITE_F(leftid);
    WRITE_F(rightid);
    WRITE_F(auto);
    WRITE_F(aggrmode);
    WRITE_F(ikelifetime);
    WRITE_F(keylife);
    WRITE_F(dpddelay);
    WRITE_F(dpdtimeout);
    WRITE_F(dpdaction);
#undef WRITE_F
    fclose(f);

    sprintf(path, "%s%s.secrets", ipsec_path, vpn->name);
    f = fopen(path, "w");
    if (!f) {
        LOG(L_DEBUG, "Can not open file '%s'", path);
        return errno;
    }
    
    fprintf(f, "%s %s : PSK \"%s\"\n",
            blobmsg_get_string(seting->_leftid),
            blobmsg_get_string(seting->_rightid),
            blobmsg_get_string(seting->_psk));

    fclose(f);

    vpn->config_pending = false;
    vpn->type->ops->enable(vpn);

    return 0;
}

static int
ipsec_policy_down(struct vpn *vpn)
{
    LOG(L_DEBUG, "ipsec policy '%s' down", vpn->name);
    struct ipsec_policy_status *status = (struct ipsec_policy_status *)vpn->status;
    /*char cmd[64] = {0};*/
    if (status->up) {
        /*sprintf(cmd, "ipsec auto --down %s &", vpn->name);*/
        /*run_cmd(cmd);*/
        add_command(500, 4, "ipsec", "auto", "--down", vpn->name);
        status->up = false;
        vlist_flush_all(&status->status);
    }
    return 0;
}

static int
ipsec_policy_up(struct vpn *vpn)
{
    LOG(L_DEBUG, "ipsec policy '%s' up", vpn->name);
    struct ipsec_policy_status *status = (struct ipsec_policy_status *)vpn->status;
    struct ipsec_policy_seting *seting = (struct ipsec_policy_seting *)vpn->seting;

    /*
     *if (status->up) {
     *    ipsec_policy_down(vpn);
     *}
     */

    if (!blobmsg_get_bool(seting->_enable)) {
        LOG(L_DEBUG, "ipsec policy '%s' disable!!", vpn->name);
        return 0;
    }

    if (status->up)
        return 0;

    /*char cmd[64] = {0};*/
    /*sprintf(cmd, "ipsec auto --up %s &", vpn->name);*/
    /*run_cmd(cmd);*/
    add_command(1000, 4, "ipsec", "auto", "--up", vpn->name);
    status->up = true;
    return 0;
}

static int
ipsec_policy_enable(struct vpn *vpn)
{
    LOG(L_DEBUG, "ipsec policy '%s' enable", vpn->name);
    /*
     *char cmd[64] = {0};
     *run_cmd("ipsec auto --rereadsecrets");
     *sprintf(cmd, "ipsec auto --replace %s", vpn->name);
     *run_cmd(cmd);
     */

    add_command(500, 3, "ipsec", "auto", "--rereadsecrets");
    add_command(500, 4, "ipsec", "auto", "--replace", vpn->name);
    return 0;
}

static int
ipsec_policy_disable(struct vpn *vpn)
{
    LOG(L_DEBUG, "ipsec policy '%s' disable", vpn->name);
    /*char cmd[64] = {0};*/
    char *path = alloca(strlen(ipsec_path) + strlen(vpn->name) + 16);

    /*sprintf(cmd, "ipsec auto --delete %s &", vpn->name);*/
    /*run_cmd(cmd);*/

    add_command(500, 4, "ipsec", "auto", "--delete", vpn->name);

    sprintf(path, "%s%s.conf", ipsec_path, vpn->name);
    unlink(path);

    sprintf(path, "%s%s.secrets", ipsec_path, vpn->name);
    unlink(path);

    return 0;
}

static int
ipsec_policy_finish(struct vpn *vpn)
{
    LOG(L_DEBUG, "ipsec policy '%s' finish", vpn->name);
    return 0;
}

static int
ipsec_policy_dump_info(struct vpn *vpn)
{
    struct ipsec_policy_seting *seting = (struct ipsec_policy_seting *)vpn->seting;
    void *a;

    blobmsg_add_string(&b, "name", vpn->name);
    blobmsg_add_string(&b, "type", vpn->type->name);
    blobmsg_add_u8(&b, "pending", vpn->config_pending);

    a = blobmsg_open_table(&b, "config");

    if (seting->_enable) {
        blobmsg_add_u8(&b, "enable", (uint8_t)blobmsg_get_bool(seting->_enable));
    }

#define DUMP_POLICY(field) \
    if (seting->_##field) { \
        blobmsg_add_string(&b, #field, (char*)blobmsg_data(seting->_##field)); \
    }

    DUMP_POLICY(right);
    DUMP_POLICY(leftsubnet);
    DUMP_POLICY(rightsubnet);
    /*DUMP_POLICY(leftsubnets);*/
    /*DUMP_POLICY(rightsubnets);*/
    DUMP_POLICY(type);
    DUMP_POLICY(authby);
    DUMP_POLICY(ike);
    DUMP_POLICY(phase2alg);
    DUMP_POLICY(phase2);
    DUMP_POLICY(leftid);
    DUMP_POLICY(rightid);
    DUMP_POLICY(auto);
    DUMP_POLICY(aggrmode);
    DUMP_POLICY(ikelifetime);
    DUMP_POLICY(keylife);
    DUMP_POLICY(psk);
    DUMP_POLICY(dpddelay);
    DUMP_POLICY(dpdtimeout);
    DUMP_POLICY(dpdaction);
#undef DUMP_POLICY

    blobmsg_close_table(&b, a);
    return 0;
}

static void
ipsec_policy_get_status(struct vpn *vpn)
{
    struct ipsec_policy_status *s = (struct ipsec_policy_status *)vpn->status;
    struct ipsec_tunnel_status *status;
    void *a;

    blob_buf_init(&b, 0);
    
    a = blobmsg_open_table(&b, "status");

    vlist_for_each_element(&s->status, status, node) {
        blobmsg_add_string(&b, "right", status->right);
        blobmsg_add_string(&b, "status", status->status);
    }
    blobmsg_close_table(&b, a);
    
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
    .enable = ipsec_policy_enable,
    .disable = ipsec_policy_disable,
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


/*
 * ------------------------------------------------------------------
 * ------------------------------------------------------------------
 */
static void
ipsec_setup_config_set(struct ipsec_setup_seting *seting, struct blob_attr *config)
{
    struct blob_attr *tb[__IPSEC_SETUP_ATTR_MAX];

    blobmsg_parse(ipsec_setup_attrs, __IPSEC_SETUP_ATTR_MAX, tb,
            blob_data(config), blob_len(config));

#define FIELD_SET(field, attr) \
    if (tb[attr]) { seting->_##field = tb[attr]; } \
    else { seting->_##field = NULL; }

    FIELD_SET(enable, IPSEC_SETUP_ATTR_ENABLE);
    FIELD_SET(plutodebug, IPSEC_SETUP_ATTR_PLUTODEBUG);
    
#undef FIELD_SET

    return;
}

static struct vpn *
ipsec_setup_create(struct vpn *vpn, struct blob_attr *config)
{
    struct ipsec_setup_seting *seting = NULL;
    struct ipsec_setup_status *status = NULL;

    seting = calloc(1, sizeof(struct ipsec_setup_seting));
    if (!seting) {
        LOG(L_WARNING, "calloc ipsec setup seting error");
        goto error;
    }

    status = calloc(1, sizeof(struct ipsec_setup_status));
    if (!status) {
        LOG(L_WARNING, "calloc ipsec setup status error");
        goto error;
    }

    ipsec_setup_config_set(seting, config);

    vpn->seting = seting;
    vpn->status = status;

    return vpn;
error:
    if (seting) { free(seting); seting = NULL; }
    if (status) { free(status); status = NULL; }
    return NULL;
}

static void
ipsec_setup_free(struct vpn *vpn)
{
    if (vpn->seting) { free(vpn->seting); vpn->seting = NULL; }
    if (vpn->status) { free(vpn->status); vpn->status = NULL; }
    return;
}

static void
ipsec_setup_change_config(struct vpn *new, struct vpn *old)
{
    struct blob_attr *old_config = old->config;
    struct ipsec_setup_seting *new_seting, *old_seting;
    bool reload = false;

    new_seting = (struct ipsec_setup_seting*)new->seting;
    old_seting = (struct ipsec_setup_seting*)old->seting;
#define CONFIG_CMP(field) \
    if (!blob_attr_equal(new_seting->_##field, old_seting->_##field)) { \
        LOG(L_DEBUG, "ipsec setup '%s' option '%s' change", new->name, #field); \
        reload = true; \
    }

    CONFIG_CMP(enable);
    CONFIG_CMP(plutodebug);
#undef CONFIG_CMP

    if (reload) {
        old->config = new->config;
        new->config = NULL;
        free(old_config);

        /** reload config */
        ipsec_setup_config_set(old_seting, old->config);
        old->config_pending = true;
    }

    vpn_free(new);

    return;
}

static void
ipsec_setup_update(struct vpn *new, struct vpn *old)
{
    if (new && old) {
        LOG(L_NOTICE, "Update ipsec setup object");
        ipsec_setup_change_config(new, old);
    } else if (old) {
        LOG(L_NOTICE, "Remove ipsec setup object");
        /** Never remove */
    } else if (new) {
        LOG(L_NOTICE, "Create ipsec setup object");
        /** do nothing */
    }
}

static int
ipsec_setup_prepare(struct vpn *vpn)
{
    LOG(L_DEBUG, "ipsec setup object prepare");
    return 0;
}

static int
ipsec_setup_config(struct vpn *vpn)
{
    LOG(L_DEBUG, "ipsec setup object config");
    struct ipsec_setup_seting *seting = (struct ipsec_setup_seting*)vpn->seting;
    struct ipsec_setup_status *status = (struct ipsec_setup_status*)vpn->status;
    char *path = alloca(strlen(ipsec_path) + strlen(vpn->name) + 16);
    FILE *f;

    if (!vpn->config_pending) {
        LOG(L_NOTICE, "ipsec setup '%s' config not pending", vpn->name);
        return -1;
    }

    sprintf(path, "%s%s.conf", ipsec_path, vpn->name);
    f = fopen(path, "w");
    if (!f) {
        LOG(L_DEBUG, "Can not open file '%s'", path);
        return errno;
    }

    fprintf(f, "config setup\n");
#define WRITE_F(field) \
    if (seting->_##field) { \
        fprintf(f, "\t%s=\"%s\"\n", #field, blobmsg_get_string(seting->_##field)); \
    }

    WRITE_F(plutodebug);
#undef WRITE_F

    vpn->config_pending = false;
    status->running = false;
    fclose(f);

    return 0;
}

static int
ipsec_setup_down(struct vpn *vpn)
{
    LOG(L_DEBUG, "ipsec setup object down");
    struct ipsec_setup_status *status = (struct ipsec_setup_status*)vpn->status;
    if (status->running) {
        /*run_cmd("/etc/init.d/ipsec stop & >/dev/null 2>&1");*/
        add_command(1000, 2, "/etc/init.d/ipsec", "stop");
        status->running = false;
    }
    return 0;
}

static int
ipsec_setup_up(struct vpn *vpn)
{
    LOG(L_DEBUG, "ipsec setup object up");
    struct ipsec_setup_seting *seting = (struct ipsec_setup_seting*)vpn->seting;
    struct ipsec_setup_status *status = (struct ipsec_setup_status*)vpn->status;
    if (blobmsg_get_bool(seting->_enable)) {
        if (!status->running) {
            /*run_cmd("/etc/init.d/ipsec restart & >/dev/null 2>&1");*/
            add_command(4000, 2, "/etc/init.d/ipsec", "restart");
            status->running = true;
        }
    } else {
        ipsec_setup_down(vpn);
    }
    return 0;
}

static int
ipsec_setup_finish(struct vpn *vpn)
{
    LOG(L_DEBUG, "ipsec setup object finish");
    return 0;
}

static int
ipsec_setup_dump_info(struct vpn *vpn)
{
    LOG(L_DEBUG, "ipsec setup object dump info");
    return 0;
}

static const struct uci_blob_param_list ipsec_setup_attr_list = {
    .n_params = __IPSEC_SETUP_ATTR_MAX,
    .params = ipsec_setup_attrs,
};

static struct vpn_ops ipsec_setup_ops = {
    .prepare = ipsec_setup_prepare,
    .config = ipsec_setup_config,
    .up = ipsec_setup_up,
    .down = ipsec_setup_down,
    .finish = ipsec_setup_finish,
    .dump_info = ipsec_setup_dump_info,
};

static struct vpn_type ipsec_setup_type = {
    .name = "ipsec_setup",
    .config_params = &ipsec_setup_attr_list,
    .create = ipsec_setup_create,
    .free = ipsec_setup_free,
    .update = ipsec_setup_update,
    .ops = &ipsec_setup_ops,
};

/** uci config */
static void
ipsec_policy_uci_section_handler(struct vpn_uci_section *s)
{
    const char *name = NULL;
    name = uci_lookup_option_string(s->uci_ctx, s->uci_section, "name");
    config_init_section(name, VPN_KIND_IPSEC, "ipsec_policy", s);
}

static void
ipsec_setup_uci_section_handler(struct vpn_uci_section *s)
{
    const char *name = NULL;
    name = s->uci_section->type;
    config_init_section(name, VPN_KIND_IPSEC, "ipsec_setup", s);
}

static struct vpn_uci_section ipsec_policy_uci_sections[] = {
    { .name = "policy", .init = ipsec_policy_uci_section_handler },
    { .name = "setup",  .init = ipsec_setup_uci_section_handler },
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
    struct vpn *vpn = container_of(obj, struct vpn, obj);
    vpn->type->ops->up(vpn);
    return 0;
}

static int
ipsec_policy_ubus_down(struct ubus_context *ctx, struct ubus_object *obj,
        struct ubus_request_data *req, const char *method,
        struct blob_attr *msg)
{
    struct vpn *vpn = container_of(obj, struct vpn, obj);
    vpn->type->ops->down(vpn);
    return 0;
}

static int
ipsec_policy_ubus_enable(struct ubus_context *ctx, struct ubus_object *obj,
        struct ubus_request_data *req, const char *method,
        struct blob_attr *msg)
{
    struct vpn *vpn = container_of(obj, struct vpn, obj);
    vpn->type->ops->config(vpn);
    vpn->type->ops->up(vpn);
    return 0;
}

static int
ipsec_policy_ubus_disable(struct ubus_context *ctx, struct ubus_object *obj,
        struct ubus_request_data *req, const char *method,
        struct blob_attr *msg)
{
    struct vpn *vpn = container_of(obj, struct vpn, obj);
    vpn->type->ops->down(vpn);
    vpn->type->ops->disable(vpn);
    return 0;
}

static int
ipsec_policy_ubus_get_status(struct ubus_context *ctx, struct ubus_object *obj,
        struct ubus_request_data *req, const char *method,
        struct blob_attr *msg)
{
    /*void *a = blobmsg_open_array(&b, "ipsec");*/

    struct vpn *vpn;
    vpn = container_of(obj, struct vpn, obj);
    ipsec_policy_get_status(vpn);
    /*
     *vlist_for_each_element(&h_vpns, vpn, node) {
     *    if (vpn->kind == VPN_KIND_IPSEC) {
     *        void *i = blobmsg_open_table(&b, NULL);
     *        blobmsg_add_string(&b, "policy", vpn->name);
     *        ipsec_policy_get_status(vpn);
     *        blobmsg_close_table(&b, i);
     *    }
     *}
     *blobmsg_close_array(&b, a);
     */
    ubus_send_reply(ctx, req, b.head);
    return 0;
}

static int
ipsec_policy_ubus_set_status(struct ubus_context *ctx, struct ubus_object *obj,
        struct ubus_request_data *req, const char *method,
        struct blob_attr *msg)
{
    struct vpn *vpn;
    struct ipsec_tunnel_status *status = NULL;
    struct ipsec_policy_status *s = NULL;
    struct blob_attr *tb[__IPSEC_STATUS_ATTR_MAX];
    char *ipsec_right, *ipsec_status;

    blobmsg_parse(ipsec_status_attrs, __IPSEC_STATUS_ATTR_MAX, tb, blob_data(msg), blob_len(msg));

    if (!tb[IPSEC_STATUS_ATTR_RIGHT] || !tb[IPSEC_STATUS_ATTR_STAT])
        return UBUS_STATUS_INVALID_ARGUMENT;

    vpn = container_of(obj, struct vpn, obj);

    status = calloc_a(sizeof(struct ipsec_tunnel_status), 
            &ipsec_right, blobmsg_data_len(tb[IPSEC_STATUS_ATTR_RIGHT])+1,
            &ipsec_status, blobmsg_data_len(tb[IPSEC_STATUS_ATTR_STAT])+1);
    if (!status) {
        LOG(L_WARNING, "ipsec tunnel '%s' status object alloc error!!!!", vpn->name);
        return UBUS_STATUS_NO_DATA;
    }

    status->right = strcpy(ipsec_right, blobmsg_data(tb[IPSEC_STATUS_ATTR_RIGHT]));
    status->status = strcpy(ipsec_status, blobmsg_data(tb[IPSEC_STATUS_ATTR_STAT]));

    s = (struct ipsec_policy_status *)vpn->status;
    vlist_add(&s->status, &status->node, status->right);

    return 0;
}

static int
ipsec_policy_ubus_dump(struct ubus_context *ctx, struct ubus_object *obj,
        struct ubus_request_data *req, const char *method,
        struct blob_attr *msg)
{
    struct vpn *vpn;

    vpn = container_of(obj, struct vpn, obj);
    blob_buf_init(&b, 0);
    ipsec_policy_dump_info(vpn);
    ubus_send_reply(ctx, req, b.head);

    return 0;
}

static struct ubus_method ipsec_policy_obj_methods[] = {
    { .name = "up", .handler = ipsec_policy_ubus_up },
    { .name = "down", .handler = ipsec_policy_ubus_down },
    { .name = "enable", .handler = ipsec_policy_ubus_enable },
    { .name = "disable", .handler = ipsec_policy_ubus_disable },
    { .name = "get_status", .handler = ipsec_policy_ubus_get_status },
    UBUS_METHOD("set_status", ipsec_policy_ubus_set_status, ipsec_status_attrs),
    /*{ .name = "set_status", .handler = ipsec_policy_ubus_set_status },*/
    { .name = "dump", .handler = ipsec_policy_ubus_dump },
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
    .dyna = true,
    .init = false,
};

/** ipsec main ubus object */
static int
ipsec_main_ubus_restart(struct ubus_context *ctx, struct ubus_object *obj,
        struct ubus_request_data *req, const char *mehtod,
        struct blob_attr *msg)
{
    LOG(L_DEBUG, "ipsec restart!!!!");
    /*run_cmd("/etc/init.d/ipsec restart");*/
    add_command(4000, 2, "/etc/init.d/ipsec", "restart");
    return 0;
}

static int
ipsec_main_ubus_reload(struct ubus_context *ctx, struct ubus_object *obj,
        struct ubus_request_data *req, const char *mehtod,
        struct blob_attr *msg)
{
    LOG(L_DEBUG, "ipsec reload!!!!");
    config_init_all();
    return 0;
}

static int
ipsec_main_ubus_start(struct ubus_context *ctx, struct ubus_object *obj,
        struct ubus_request_data *req, const char *mehtod,
        struct blob_attr *msg)
{
    /*run_cmd("/etc/init.d/ipsec start");*/
    add_command(4000, 2, "/etc/init.d/ipsec", "start");
    return 0;
}

static int
ipsec_main_ubus_stop(struct ubus_context *ctx, struct ubus_object *obj,
        struct ubus_request_data *req, const char *mehtod,
        struct blob_attr *msg)
{
    /*run_cmd("/etc/init.d/ipsec stop");*/
    add_command(2000, 2, "/etc/init.d/ipsec", "stop");
    return 0;
}

static struct ubus_method ipsec_main_obj_methods[] = {
    { .name = "restart", .handler = ipsec_main_ubus_restart },
    { .name = "reload", .handler = ipsec_main_ubus_reload },
    { .name = "start", .handler = ipsec_main_ubus_start },
    { .name = "stop", .handler = ipsec_main_ubus_stop },
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
    .dyna = false,
    .init = true,
};


/*
 * ----------------------------------------------------
 */
static int
ipsec_setup_ubus_dump(struct ubus_context *ctx, struct ubus_object *obj,
        struct ubus_request_data *req, const char *method,
        struct blob_attr *msg)
{
    LOG(L_DEBUG, "ipsec.setup dump!!!");
    return 0;
}

static struct ubus_method ipsec_setup_obj_methods[] = {
    { .name = "dump", .handler = ipsec_setup_ubus_dump },
};

static struct ubus_object_type ipsec_setup_obj_type = 
    UBUS_OBJECT_TYPE("ipsec_setup", ipsec_setup_obj_methods);

static struct ubus_object ipsec_setup_obj = {
    .name = "ipsec.setup",
    .type = &ipsec_setup_obj_type,
    .methods = ipsec_setup_obj_methods,
    .n_methods = ARRAY_SIZE(ipsec_setup_obj_methods),
};

static struct vpn_ubus_obj ipsec_ubus_setup_obj = {
    .name = "ipsec.setup",
    .ubus = &ipsec_setup_obj,
    .dyna = true,
    .init = false,
};

/** event **/
static void
ipsec_event_handler(char *action, char *net)
{
    struct vpn *vpn;
    struct ipsec_policy_seting *seting;

    if (!strcmp(action, "ifup")) {
        LOG(L_DEBUG, "net '%s' is UP", net);
        vlist_for_each_element(&h_vpns, vpn, node) {
            seting = (struct ipsec_policy_seting*)vpn->seting;
            if (!strcmp(vpn->type->name, "ipsec_policy") 
                    && !strcmp(net, blobmsg_data(seting->_left))) {
                ipsec_policy_left_get(vpn, net);
                vpn->type->ops->config(vpn);
                vpn->type->ops->up(vpn);
            }
        }
    } else if (!strcmp(action, "ifdown")) {
        LOG(L_DEBUG, "net '%s' is DOWN", net);
    }
}

static void
ipsec_event_receive_cb(struct ubus_context *ctx, struct ubus_event_handler *ev,
        const char *type, struct blob_attr *msg)
{
    enum {
        EV_ACTION,
        EV_IFNAME,
        __EV_MAX
    };
    static const struct blobmsg_policy ev_policy[__EV_MAX] = {
        [EV_ACTION] = { .name = "action", .type = BLOBMSG_TYPE_STRING },
        [EV_IFNAME] = { .name = "interface", .type = BLOBMSG_TYPE_STRING },
    };
    struct blob_attr *tb[__EV_MAX];

    blobmsg_parse(ev_policy, __EV_MAX, tb, blob_data(msg), blob_len(msg));

    ipsec_event_handler(blobmsg_get_string(tb[EV_ACTION]),
            blobmsg_get_string(tb[EV_IFNAME]));
}

static void
ipsec_event_listen(void)
{
    static struct ubus_event_handler listener;
    int ret;

    memset(&listener, 0, sizeof(listener));
    listener.cb = ipsec_event_receive_cb;

    ret = ubus_register_event_handler(ubus_ctx, &listener, "network.interface");
    if (ret) {
        LOG(L_WARNING, "register event handler failed: %s", ubus_strerror(ret));
        return;
    }
}

void
ipsec_init(void)
{
    ipsec_event_listen();
}

void
ipsec_final(void)
{
    char cmd[64] = {0};
    sprintf(cmd, "/etc/init.d/ipsec stop");
    run_cmd(cmd);
}

static void 
ipsec_file_init(void)
{
    char *path = alloca(strlen(ipsec_path) + 16);
    if (0 != access(ipsec_path, F_OK)) {
        mkdir(ipsec_path, 0777);
    } else {
        sprintf(path, "%s*", ipsec_path);
        unlink(path);
    }
}

/** init */
static void __init 
ipsec_type_init(void)
{
    ipsec_file_init();
    vpn_uci_package_register(&ipsec_uci);
    vpn_type_register(&ipsec_policy_type);
    vpn_type_register(&ipsec_setup_type);
    vpn_ubus_obj_register(&ipsec_ubus_main_obj);
    vpn_ubus_obj_register(&ipsec_ubus_policy_obj);
    vpn_ubus_obj_register(&ipsec_ubus_setup_obj);
}


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

/**
 * ipsec policy seting object
 */
struct ipsec_policy_seting {
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
#define IPSEC_LINK_MAX  4

static const char ipsec_link_class[4][8] = {
    { "ipsec0" },
    { "ipsec1" },
    { "ipsec2" },
    { "ipsec3" },
};

struct ipsec_setup_link {
    char ifname[64];
    char l3_device[64];
    bool active;
};

struct ipsec_setup_seting {
    struct ipsec_setup_link link[IPSEC_LINK_MAX];
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
};

enum {
    IPSEC_SETUP_ATTR_IPSEC0,
    IPSEC_SETUP_ATTR_IPSEC1,
    IPSEC_SETUP_ATTR_IPSEC2,
    IPSEC_SETUP_ATTR_IPSEC3,
    __IPSEC_SETUP_ATTR_MAX
};

/**
 * ipsec setup configure attr list
 */
static const struct blobmsg_policy ipsec_setup_attrs[__IPSEC_SETUP_ATTR_MAX] = {
    [IPSEC_SETUP_ATTR_IPSEC0] = { .name = "ipsec0", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_SETUP_ATTR_IPSEC1] = { .name = "ipsec1", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_SETUP_ATTR_IPSEC2] = { .name = "ipsec2", .type = BLOBMSG_TYPE_STRING },
    [IPSEC_SETUP_ATTR_IPSEC3] = { .name = "ipsec3", .type = BLOBMSG_TYPE_STRING },
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
    if (tb[attr]) { seting->_##field = tb[attr]; }

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
    char *path = alloca(strlen(ipsec_path) + strlen(vpn->name) + 16);

    vpn->type->ops->down(vpn);

    sprintf(path, "%s%s.conf", ipsec_path, vpn->name);
    unlink(path);
    sprintf(path, "%s%s.secrets", ipsec_path, vpn->name);
    unlink(path);

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

static int
ipsec_policy_config(struct vpn *vpn)
{
    LOG(L_DEBUG, "ipsec policy '%s' config", vpn->name);
    struct ipsec_policy_seting *seting = (struct ipsec_policy_seting *)vpn->seting;
    char *path = alloca(strlen(ipsec_path) + strlen(vpn->name) + 16);
    FILE *f;
    if (!vpn->config_pending) {
        LOG(L_NOTICE, "ipsec policy '%s' config not pending", vpn->name);
        return 0;
    }

    sprintf(path, "%s%s.conf", ipsec_path, vpn->name);
    f = fopen(path, "w");
    if (!f) {
        LOG(L_DEBUG, "Can not open file '%s'", path);
        return errno;
    }

    fprintf(f, "conn %s\n", vpn->name);
#define WRITE_F(field) \
    if (seting->_##field) { \
        fprintf(f, "\t%s=%s\n", #field, blobmsg_get_string(seting->_##field)); \
    }

    WRITE_F(left);
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

    return 0;
}

static int
ipsec_policy_down(struct vpn *vpn)
{
    LOG(L_DEBUG, "ipsec policy '%s' down", vpn->name);
    struct ipsec_policy_status *status = (struct ipsec_policy_status *)vpn->status;
    char cmd[64] = {0};
    sprintf(cmd, "ipsec auto --down %s &", vpn->name);
#if 0
    system(cmd);
#endif
    status->up = false;
    vlist_flush_all(&status->status);
    return 0;
}

static int
ipsec_policy_up(struct vpn *vpn)
{
    LOG(L_DEBUG, "ipsec policy '%s' up", vpn->name);
    struct ipsec_policy_status *status = (struct ipsec_policy_status *)vpn->status;
    if (status->up) {
        ipsec_policy_down(vpn);
    }
    char cmd[64] = {0};
    sprintf(cmd, "ipsec auto --up %s &", vpn->name);
#if 0
    system(cmd);
#endif
    status->up = true;
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
    
    a = blobmsg_open_array(&b, "status");

    vlist_for_each_element(&s->status, status, node) {
        blobmsg_add_string(&b, "right", status->right);
        blobmsg_add_string(&b, "status", status->status);
    }
    blobmsg_close_array(&b, a);
    
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


/*
 * ------------------------------------------------------------------
 */
static void
ipsec_setup_config_set(struct ipsec_setup_seting *seting, struct blob_attr *config)
{
    struct blob_attr *tb[__IPSEC_SETUP_ATTR_MAX];

    blobmsg_parse(ipsec_setup_attrs, __IPSEC_SETUP_ATTR_MAX, tb,
            blob_data(config), blob_len(config));

    if (tb[IPSEC_SETUP_ATTR_IPSEC0]) {
        strncpy(seting->link[0].ifname, 
                blobmsg_data(tb[IPSEC_SETUP_ATTR_IPSEC0]), sizeof(seting->link[0])-1);
        /*LOG(L_DEBUG, "ipsec0=%s", seting->link[0].ifname);*/
    }
    if (tb[IPSEC_SETUP_ATTR_IPSEC1]) {
        strncpy(seting->link[1].ifname, 
                blobmsg_data(tb[IPSEC_SETUP_ATTR_IPSEC1]), sizeof(seting->link[1])-1);
        /*LOG(L_DEBUG, "ipsec1=%s", seting->link[1].ifname);*/
    }
    if (tb[IPSEC_SETUP_ATTR_IPSEC2]) {
        strncpy(seting->link[2].ifname, 
                blobmsg_data(tb[IPSEC_SETUP_ATTR_IPSEC2]), sizeof(seting->link[2])-1);
        /*LOG(L_DEBUG, "ipsec2=%s", seting->link[2].ifname);*/
    }
    if (tb[IPSEC_SETUP_ATTR_IPSEC3]) {
        strncpy(seting->link[3].ifname, 
                blobmsg_data(tb[IPSEC_SETUP_ATTR_IPSEC3]), sizeof(seting->link[3])-1);
        /*LOG(L_DEBUG, "ipsec3=%s", seting->link[3].ifname);*/
    }

    return;
}

static struct vpn *
ipsec_setup_create(struct vpn *vpn, struct blob_attr *config)
{
    struct ipsec_setup_seting *seting = NULL;

    seting = calloc(1, sizeof(struct ipsec_setup_seting));
    if (!seting) {
        LOG(L_WARNING, "calloc ipsec setup seting error");
        goto error;
    }

    ipsec_setup_config_set(seting, config);

    vpn->seting = seting;
    vpn->status = NULL;

    return vpn;
error:
    if (!seting) { free(seting); seting = NULL; }
    return NULL;
}

static void
ipsec_setup_free(struct vpn *vpn)
{
    return;
/*
 *    struct ipsec_setup_seting *seting = (struct ipsec_setup_seting *)vpn->seting;
 *    int i = 0;
 *
 *    if (!seting)
 *        return;
 *
 *    for (i=0; i<IPSEC_LINK_MAX; ++i) {
 *        if (seting->link[i].ifname) {
 *            free(seting->link[i].ifname);
 *            seting->link[i].ifname = NULL;
 *        }
 *        if (seting->link[i].l3_device) {
 *            free(seting->link[i].l3_device);
 *            seting->link[i].l3_device = NULL;
 *        }
 *    }
 */
}

static void
ipsec_setup_change_config(struct vpn *new, struct vpn *old)
{
    struct blob_attr *old_config = old->config;
    struct ipsec_setup_seting *new_seting, *old_seting;
    int i = 0;
    bool reload = false;

    new_seting = (struct ipsec_setup_seting*)new->seting;
    old_seting = (struct ipsec_setup_seting*)old->seting;
    for (i=0; i<IPSEC_LINK_MAX; ++i) {
        if (strcmp(new_seting->link[i].ifname, old_seting->link[i].ifname)) {
            reload = true;
            break;
        }
    }

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
    char *path = alloca(strlen("/etc/ipsec.conf") + 1);
    int i = 0;
    FILE *f;

    if (!vpn->config_pending) {
        LOG(L_NOTICE, "ipsec setup '%s' config not pending", vpn->name);
        return 0;
    }

    sprintf(path, "/etc/ipsec.conf");
    f = fopen(path, "w");
    if (!f) {
        LOG(L_DEBUG, "Can not open file '%s'", path);
        return errno;
    }

    fprintf(f, "version 2\n\n");
    fprintf(f, "config setup\n");
    fprintf(f, "\tinterface=\"");
    for (i=0; i<IPSEC_LINK_MAX; ++i) {
        if (seting->link[i].ifname[0] != '\0') {
            fprintf(f, "ipsec%d=%s ", i, seting->link[i].ifname);
        }
    }
    fprintf(f, "\"\n");

    vpn->config_pending = false;
    fclose(f);

    return 0;
}

static int
ipsec_setup_down(struct vpn *vpn)
{
    LOG(L_DEBUG, "ipsec setup object down");
    return 0;
}

static int
ipsec_setup_up(struct vpn *vpn)
{
    LOG(L_DEBUG, "ipsec setup object up");
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
    struct vpn *vpn = NULL;
    struct ipsec_setup_seting *seting = NULL;
    int i = 0;
    void *a;

    vpn = container_of(obj, struct vpn, obj);
    seting = (struct ipsec_setup_seting *)vpn->seting;

    blob_buf_init(&b, 0);
    a = blobmsg_open_table(&b, "link");
    for (i=0; i<IPSEC_LINK_MAX; ++i) {
        blobmsg_add_string(&b, ipsec_link_class[i], seting->link[i].ifname);
    }
    blobmsg_close_table(&b, a);

    ubus_send_reply(ctx, req, b.head);

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


/** init */
static void __init 
ipsec_type_init(void)
{
    vpn_uci_package_register(&ipsec_uci);
    vpn_type_register(&ipsec_policy_type);
    vpn_type_register(&ipsec_setup_type);
    vpn_ubus_obj_register(&ipsec_ubus_main_obj);
    vpn_ubus_obj_register(&ipsec_ubus_policy_obj);
    vpn_ubus_obj_register(&ipsec_ubus_setup_obj);
}


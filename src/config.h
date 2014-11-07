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

#ifndef __VPND_CONFIG_H__
#define __VPND_CONFIG_H__


struct vpn_uci_package;

struct vpn_uci_section {
    const char *name;
    struct uci_context *uci_ctx;
    struct uci_section *uci_section;
    struct vpn_uci_package *package;
    void (*init)(struct vpn_uci_section *);
};

struct vpn_uci_package {
    struct list_head list;
    struct uci_context *uci_ctx;
    struct uci_package *uci_package;

    const char *name;
    struct vpn_uci_section *sections;
    int n_sections;
};

void vpn_uci_package_register(struct vpn_uci_package *p);
void vpn_uci_package_unregister(struct vpn_uci_package *p);

void config_init_section(const char *name, enum vpn_kind kind, const char *vpn_type, struct vpn_uci_section *s);
void config_init_all(void);
#endif /** __VPND_CONFIG_H__ */


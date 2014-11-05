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

#ifndef __VPND_UBUS_H__
#define __VPND_UBUS_H__

#include "vpn.h"

int vpnd_ubus_init(const char *path);
void vpnd_ubus_done(void);
void vpn_ubus_add_object(struct vpn *vpn);
void vpn_ubus_obj_register(struct vpn_ubus_obj *obj);
void vpn_ubus_obj_unregister(struct vpn_ubus_obj *obj);
struct vpn_ubus_obj *vpn_ubus_obj_lookup(const char *path);

#endif /** __VPND_UBUS_H__ */


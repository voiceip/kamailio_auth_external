/*
 * Copyright (C) 2018 Kinshuk
 *
 * This file is part of Kamailio, a free SIP server.
 *
 * Kamailio is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version
 *
 * Kamailio is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program; if not, write to the Free Software 
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Exception: permission to copy, modify, propagate, and distribute a work
 * formed by combining OpenSSL toolkit software and the code in this file,
 * such as linking with software components and libraries released under
 * OpenSSL project license.
 *
 */
#ifndef AUTHJWT_H
#define AUTHJWT_H

#include "../../core/locking.h"
#include "../../core/str.h"
#include "../../modules/auth/api.h"

typedef struct AuthJWTParams{
    char *key_filepath;
} AuthJWTParams;
 
extern auth_api_s_t eph_auth_api;

extern gen_lock_t *authjwt_secret_lock;
#define SECRET_LOCK	lock_get(authjwt_secret_lock)
#define SECRET_UNLOCK	lock_release(authjwt_secret_lock)

#endif /* AUTHJWT_H */

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

#include <sys/time.h>
#include <stdlib.h>

#include "../../core/dprint.h"
#include "../../core/locking.h"
#include "../../core/mod_fix.h"
#include "../../core/sr_module.h"
#include "../../core/str.h"
#include "../../core/kemi.h"
#include "../../modules/auth/api.h"

#include "auth_jwt.h"
#include "authorize.h"
#include "checks.h"

MODULE_VERSION

static int mod_init(void);
static int mod_destroy(void);

static AuthJWTParams jwt_params= {};

static cmd_export_t commands[] = {
    { "authjwt_check", (cmd_function) authjwt_check,
      1, fixup_var_str_1, 0,
      REQUEST_ROUTE },
    { "authjwt_www", (cmd_function) authjwt_www,
      1, fixup_var_str_1, 0,
      REQUEST_ROUTE },
    { "authjwt_www", (cmd_function) authjwt_www2,
      2, fixup_var_str_12, 0,
      REQUEST_ROUTE },
    { "authjwt_proxy", (cmd_function) authjwt_proxy,
      1, fixup_var_str_1, 0,
      REQUEST_ROUTE },
    { "authjwt_authenticate", (cmd_function) authjwt_authenticate,
      2, fixup_var_str_12, 0,
      REQUEST_ROUTE },
    { "authjwt_check_from", (cmd_function) authjwt_check_from0,
      0, 0, 0,
      REQUEST_ROUTE },
    { "authjwt_check_from", (cmd_function) authjwt_check_from1,
      1, fixup_var_str_1, 0,
      REQUEST_ROUTE },
    { "authjwt_check_to", (cmd_function) authjwt_check_to0,
      0, 0, 0,
      REQUEST_ROUTE },
    { "authjwt_check_to", (cmd_function) authjwt_check_to1,
      1, fixup_var_str_1, 0,
      REQUEST_ROUTE },
    {0, 0, 0, 0, 0, 0}
};

static param_export_t parameters[] = {
    {"key_filepath", STR_PARAM, &(jwt_params.key_filepath)},
    {0, 0, 0}
};

struct module_exports exports = {
    "auth_external",    // module name
    DEFAULT_DLFLAGS, // dlopen flags
    commands,        // exported functions
    parameters,      // exported parameters
    NULL,            // exported statistics
    NULL,            // exported MI functions
    NULL,            // exported seudo-variables
    NULL,            // extra processes
    mod_init,        // module init function (before fork. kids will inherit)
    NULL,            // reply processing function
    (destroy_function) mod_destroy,     // destroy function
    NULL       // child init function
};


auth_api_s_t eph_auth_api;

static int mod_init(void)
{
    bind_auth_s_t bind_auth;

    bind_auth = (bind_auth_s_t) find_export("bind_auth_s", 0, 0);
    if (bind_auth)
    {
        if (bind_auth(&eph_auth_api) < 0)
        {
            LM_ERR("unable to bind to auth module\n");
            return -1;
        }
    }
    else
    {
        memset(&eph_auth_api, 0, sizeof(auth_api_s_t));
        LM_INFO("auth module not loaded - digest authentication and "
            "check functions will not be available\n");
    }

    LM_INFO("AuthJWT Init Complete");
    return 0;
}

/**
* destroy module function
*/
static int mod_destroy(void)
{
    //statsd_destroy();
    LM_INFO("AuthJWT Destroying...");
    return 0;
}
 




/**
 *
 */
/* clang-format off */
static sr_kemi_t sr_kemi_auth_ephemeral_exports[] = {
	{ str_init("auth_jwt"), str_init("authjwt_check"),
		SR_KEMIP_INT, ki_authjwt_check,
		{ SR_KEMIP_STR, SR_KEMIP_NONE, SR_KEMIP_NONE,
			SR_KEMIP_NONE, SR_KEMIP_NONE, SR_KEMIP_NONE }
	},
	{ str_init("auth_jwt"), str_init("authjwt_www"),
		SR_KEMIP_INT, ki_authjwt_www,
		{ SR_KEMIP_STR, SR_KEMIP_NONE, SR_KEMIP_NONE,
			SR_KEMIP_NONE, SR_KEMIP_NONE, SR_KEMIP_NONE }
	},
	{ str_init("auth_jwt"), str_init("authjwt_www_method"),
		SR_KEMIP_INT, ki_authjwt_www_method,
		{ SR_KEMIP_STR, SR_KEMIP_STR, SR_KEMIP_NONE,
			SR_KEMIP_NONE, SR_KEMIP_NONE, SR_KEMIP_NONE }
	},
	{ str_init("auth_jwt"), str_init("authjwt_proxy"),
		SR_KEMIP_INT, ki_authjwt_proxy,
		{ SR_KEMIP_STR, SR_KEMIP_NONE, SR_KEMIP_NONE,
			SR_KEMIP_NONE, SR_KEMIP_NONE, SR_KEMIP_NONE }
	},
	{ str_init("auth_jwt"), str_init("authjwt_authenticate"),
		SR_KEMIP_INT, ki_authjwt_authenticate,
		{ SR_KEMIP_STR, SR_KEMIP_STR, SR_KEMIP_NONE,
			SR_KEMIP_NONE, SR_KEMIP_NONE, SR_KEMIP_NONE }
	},

	{ {0, 0}, {0, 0}, 0, NULL, { 0, 0, 0, 0, 0, 0 } }
};
/* clang-format on */

int mod_register(char *path, int *dlflags, void *p1, void *p2)
{
	sr_kemi_modules_add(sr_kemi_auth_ephemeral_exports);
	return 0;
}
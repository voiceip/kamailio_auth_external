/*
 * $Id$
 *
 * Copyright (C) 2013 Crocodile RCS Ltd
 * Copyright (C) 2017 ng-voice GmbH
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
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "../../core/basex.h"
#include "../../core/dprint.h"
#include "../../core/mod_fix.h"
#include "../../core/str.h"
#include "../../core/ut.h"
#include "../../core/parser/digest/digest.h"
#include "../../core/parser/hf.h"
#include "../../core/mod_fix.h"

#include "auth_jwt.h"
#include "authorize.h"

 
static inline int get_ha1(struct username *_username, str *_domain,
				str *_secret, char *_ha1)
{
	char password[base64_enc_len(SHA512_DIGEST_LENGTH)];
	str spassword;

	spassword.s = (char *) password;
	spassword.len = 0;

	// if (get_pass(&_username->whole, _secret, &spassword) < 0)
	// {
	// 	LM_ERR("calculating password\n");
	// 	return -1;
	// }

	eph_auth_api.calc_HA1(HA_MD5, &_username->whole, _domain, &spassword,
				0, 0, _ha1);
	LM_DBG("calculated HA1: %s\n", _ha1);

	return 0;
}

static inline int do_auth(struct sip_msg *_m, struct hdr_field *_h, str *_realm,
			str *_method, str *_secret)
{
	auth_result_t ret;
	char ha1[512];
	auth_body_t *cred = (auth_body_t*) _h->parsed;

	LM_DBG("secret: %.*s (%i)\n", _secret->len, _secret->s, _secret->len);

	if (get_ha1(&cred->digest.username, _realm, _secret, ha1) < 0)
	{
		LM_ERR("calculating HA1\n");
		return AUTH_ERROR;
	}

	LM_DBG("HA1: %i\n", (int)strlen(ha1));
	
	ret = eph_auth_api.check_response(&cred->digest, _method, ha1);
	if (ret == AUTHENTICATED)
	{
		if (eph_auth_api.post_auth(_m, _h, ha1) != AUTHENTICATED) {
			return AUTH_ERROR;
		}
		return AUTH_OK;
	} else if (ret == NOT_AUTHENTICATED) {
		return AUTH_INVALID_PASSWORD;
	} else {
		return AUTH_ERROR;
	}
}

 

static inline int digest_authenticate(struct sip_msg *_m, str *_realm,
				hdr_types_t _hftype, str *_method)
{
	struct hdr_field* h;
	auth_cfg_result_t ret = AUTH_ERROR;
	auth_result_t rauth;
	struct secret *secret_struct;
	str username;

	LM_DBG("realm: %.*s\n", _realm->len, _realm->s);
	LM_DBG("method: %.*s\n", _method->len, _method->s);

	rauth = eph_auth_api.pre_auth(_m, _realm, _hftype, &h, NULL);
	switch(rauth)
	{
	case NONCE_REUSED:
		LM_DBG("nonce reused\n");
		return AUTH_NONCE_REUSED;
	case STALE_NONCE:
		LM_DBG("stale nonce\n");
		return AUTH_STALE_NONCE;
	case NO_CREDENTIALS:
		LM_DBG("no credentials\n");
		return AUTH_NO_CREDENTIALS;
	case ERROR:
	case BAD_CREDENTIALS:
		LM_DBG("error or bad credentials\n");
		return AUTH_ERROR;
	case CREATE_CHALLENGE:
		LM_ERR("CREATE_CHALLENGE is not a valid state\n");
		return AUTH_ERROR;
	case DO_RESYNCHRONIZATION:
		LM_ERR("DO_RESYNCHRONIZATION is not a valid state\n");
		return AUTH_ERROR;
	case NOT_AUTHENTICATED:
		LM_DBG("not authenticated\n");
		return AUTH_ERROR;
	case DO_AUTHENTICATION:
		break;
	case AUTHENTICATED:
		return AUTH_OK;
	}

	username = ((auth_body_t *) h->parsed)->digest.username.whole;
	LM_DBG("username: %.*s\n", username.len, username.s);

	if (authjwt_verify_timestamp(&username) < 0)
	{
		LM_ERR("invalid timestamp in username\n");
		return AUTH_ERROR;
	}

	// SECRET_LOCK;
	// secret_struct = secret_list;
	// while (secret_struct != NULL)
	// {
	// 	ret = do_auth(_m, h, _realm, _method,
	// 			&secret_struct->secret_key);
	// 	if (ret == AUTH_OK)
	// 	{
	// 		break;
	// 	}
	// 	secret_struct = secret_struct->next;
	// }
	// SECRET_UNLOCK;

	return ret;
}

int ki_authjwt_check(sip_msg_t *_m, str *srealm)
{

	if (eph_auth_api.pre_auth == NULL)
	{
		LM_ERR("authjwt_check() cannot be used without the auth "
			"module\n");
		return AUTH_ERROR;
	}

	if (_m->REQ_METHOD == METHOD_ACK || _m->REQ_METHOD == METHOD_CANCEL)
	{
		return AUTH_OK;
	}

	if (srealm->len == 0)
	{
		LM_ERR("invalid realm parameter - empty value\n");
		return AUTH_ERROR;
	}

	if (_m->REQ_METHOD == METHOD_REGISTER)
	{
		return digest_authenticate(_m, srealm, HDR_AUTHORIZATION_T,
					&_m->first_line.u.request.method);
	}
	else
	{
		return digest_authenticate(_m, srealm, HDR_PROXYAUTH_T,
					&_m->first_line.u.request.method);
	}
}

int authjwt_check(struct sip_msg *_m, char *_realm, char *_p2)
{
	str srealm;

	if(_m == NULL || _realm == NULL)
	{
		LM_ERR("invalid parameters\n");
		return AUTH_ERROR;
	}

	if (get_str_fparam(&srealm, _m, (fparam_t*)_realm) < 0)
	{
		LM_ERR("failed to get realm value\n");
		return AUTH_ERROR;
	}

	return ki_authjwt_check(_m, &srealm);
}

int ki_authjwt_www(sip_msg_t *_m, str *srealm)
{
	if (eph_auth_api.pre_auth == NULL)
	{
		LM_ERR("authjwt_www() cannot be used without the auth "
			"module\n");
		return AUTH_ERROR;
	}

	if (_m->REQ_METHOD == METHOD_ACK || _m->REQ_METHOD == METHOD_CANCEL)
	{
		return AUTH_OK;
	}

	if (srealm->len == 0)
	{
		LM_ERR("invalid realm parameter - empty value\n");
		return AUTH_ERROR;
	}

	return digest_authenticate(_m, srealm, HDR_AUTHORIZATION_T,
					&_m->first_line.u.request.method);
}

int authjwt_www(struct sip_msg *_m, char *_realm, char *_p2)
{
	str srealm;

	if(_m == NULL || _realm == NULL)
	{
		LM_ERR("invalid parameters\n");
		return AUTH_ERROR;
	}

	if (get_str_fparam(&srealm, _m, (fparam_t*)_realm) < 0)
	{
		LM_ERR("failed to get realm value\n");
		return AUTH_ERROR;
	}

	return ki_authjwt_www(_m, &srealm);
}

int ki_authjwt_www_method(sip_msg_t *_m, str *srealm, str *smethod)
{
	if (eph_auth_api.pre_auth == NULL)
	{
		LM_ERR("authjwt_www() cannot be used without the auth "
			"module\n");
		return AUTH_ERROR;
	}

	if (_m->REQ_METHOD == METHOD_ACK || _m->REQ_METHOD == METHOD_CANCEL)
	{
		return AUTH_OK;
	}

	if (srealm->len == 0)
	{
		LM_ERR("invalid realm parameter - empty value\n");
		return AUTH_ERROR;
	}

	if (smethod->len == 0)
	{
		LM_ERR("invalid method value - empty value\n");
		return AUTH_ERROR;
	}

	return digest_authenticate(_m, srealm, HDR_AUTHORIZATION_T, smethod);
}

int authjwt_www2(struct sip_msg *_m, char *_realm, char *_method)
{
	str srealm;
	str smethod;

	if(_m == NULL || _realm == NULL || _method == NULL)
	{
		LM_ERR("invalid parameters\n");
		return AUTH_ERROR;
	}

	if (get_str_fparam(&srealm, _m, (fparam_t*)_realm) < 0)
	{
		LM_ERR("failed to get realm value\n");
		return AUTH_ERROR;
	}

	if (get_str_fparam(&smethod, _m, (fparam_t*)_method) < 0)
	{
		LM_ERR("failed to get method value\n");
		return AUTH_ERROR;
	}

	return ki_authjwt_www_method(_m, &srealm, &smethod);
}

int ki_authjwt_proxy(sip_msg_t *_m, str *srealm)
{
	if (eph_auth_api.pre_auth == NULL)
	{
		LM_ERR("authjwt_proxy() cannot be used without the auth "
			"module\n");
		return AUTH_ERROR;
	}

	if (_m->REQ_METHOD == METHOD_ACK || _m->REQ_METHOD == METHOD_CANCEL)
	{
		return AUTH_OK;
	}

	if (srealm->len == 0)
	{
		LM_ERR("invalid realm parameter - empty value\n");
		return AUTH_ERROR;
	}

	return digest_authenticate(_m, srealm, HDR_PROXYAUTH_T,
					&_m->first_line.u.request.method);
}

int authjwt_proxy(struct sip_msg *_m, char *_realm, char *_p2)
{
	str srealm;

	if(_m == NULL || _realm == NULL)
	{
		LM_ERR("invalid parameters\n");
		return AUTH_ERROR;
	}

	if (get_str_fparam(&srealm, _m, (fparam_t*)_realm) < 0)
	{
		LM_ERR("failed to get realm value\n");
		return AUTH_ERROR;
	}

	return ki_authjwt_proxy(_m, &srealm);
}

int ki_authjwt_authenticate(sip_msg_t *_m, str *susername, str *spassword)
{
	char generated_password[base64_enc_len(SHA_DIGEST_LENGTH)];
	str sgenerated_password;
	struct secret *secret_struct;

	if (susername->len == 0)
	{
		LM_ERR("invalid username parameter - empty value\n");
		return AUTH_ERROR;
	}

	if (spassword->len == 0)
	{
		LM_ERR("invalid password parameter - empty value\n");
		return AUTH_ERROR;
	}

	if (authjwt_verify_timestamp(susername) < 0)
	{
		LM_ERR("invalid timestamp in username\n");
		return AUTH_ERROR;
	}

	LM_DBG("username: %.*s\n", susername->len, susername->s);
	LM_DBG("password: %.*s\n", spassword->len, spassword->s);

	sgenerated_password.s = generated_password;
	SECRET_LOCK;
	secret_struct = secret_list;
	while (secret_struct != NULL)
	{
		LM_DBG("trying secret: %.*s\n",
			secret_struct->secret_key.len,
			secret_struct->secret_key.s);
		if (get_pass(susername, &secret_struct->secret_key,
				&sgenerated_password) == 0)
		{
			LM_DBG("generated password: %.*s\n",
				sgenerated_password.len, sgenerated_password.s);
			if (strncmp(spassword->s, sgenerated_password.s,
					spassword->len) == 0)
			{
				SECRET_UNLOCK;
				return AUTH_OK;
			}
		}
		secret_struct = secret_struct->next;
	}
	SECRET_UNLOCK;

	return AUTH_ERROR;
}

int authjwt_authenticate(struct sip_msg *_m, char *_username, char *_password)
{
	str susername, spassword;

	if (_m == NULL || _username == NULL || _password == NULL)
	{
		LM_ERR("invalid parameters\n");
		return AUTH_ERROR;
	}

	if (get_str_fparam(&susername, _m, (fparam_t*)_username) < 0)
	{
		LM_ERR("failed to get username value\n");
		return AUTH_ERROR;
	}

	if (get_str_fparam(&spassword, _m, (fparam_t*)_password) < 0)
	{
		LM_ERR("failed to get password value\n");
		return AUTH_ERROR;
	}

	return ki_authjwt_authenticate(_m, &susername, &spassword);
}

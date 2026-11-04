/*
 * JCOP specific operation for PKCS15 initialization
 *
 * Copyright 2003 Chaskiel Grundman <cg2v@andrew.cmu.edu>
 * Copyright (C) 2002 Olaf Kirch <okir@suse.de>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "config.h"

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>

#include "libopensc/opensc.h"
#include "libopensc/cardctl.h"
#include "libopensc/log.h"
#include "pkcs15-init.h"
#include "profile.h"

#define JCOP_MAX_PINS            3
#define JCOP_USER_PIN_REF        1
#define JCOP_SO_PIN_REF          2

/*
 * Erase the card
 */
static int
jcop_erase_card(struct sc_profile *pro, sc_pkcs15_card_t *p15card) {
     /* later */
     return SC_ERROR_NOT_SUPPORTED;
}


/*
 * The PKCS#15 application DF is the applet instance itself. It is created
 * when the applet is installed with GlobalPlatform, which needs the card
 * manager keys, so it cannot be created here. Accept it if it exists.
 */
static int
jcop_create_dir(sc_profile_t *profile, sc_pkcs15_card_t *p15card, sc_file_t *file)
{
	struct sc_card *card = p15card->card;
	int r;

	LOG_FUNC_CALLED(card->ctx);
	if (file->type != SC_FILE_TYPE_DF)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_NOT_SUPPORTED);

	r = sc_select_file(card, &file->path, NULL);
	if (r == SC_ERROR_FILE_NOT_FOUND)
		sc_log(card->ctx, "DF missing, the PKCS#15 applet is not installed");
	LOG_FUNC_RETURN(card->ctx, r);
}


/*
 * Select a PIN reference
 *
 * The applet has two PINs, both set when the applet is installed:
 * the user PIN with reference 1 and the SO PIN with reference 2.
 */
static int
jcop_select_pin_reference(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
		sc_pkcs15_auth_info_t *auth_info)
{
	int preferred;

	if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		return SC_ERROR_OBJECT_NOT_VALID;

	if (auth_info->attrs.pin.flags & SC_PKCS15_PIN_FLAG_SO_PIN)
		preferred = JCOP_SO_PIN_REF;
	else
		preferred = JCOP_USER_PIN_REF;

	if (auth_info->attrs.pin.reference > preferred)
		return SC_ERROR_TOO_MANY_OBJECTS;
	auth_info->attrs.pin.reference = preferred;
	return SC_SUCCESS;
}

/*
 * Store a PIN
 *
 * The PIN values are set by the GlobalPlatform install of the applet and
 * there is no separate PUK. Only verify the given PIN, so a wrong PIN is
 * caught before the PIN object is written to the AODF. Change a PIN later
 * with CHANGE REFERENCE DATA (pkcs15-tool --change-pin).
 */
static int
jcop_create_pin(sc_profile_t *profile, sc_pkcs15_card_t *p15card, sc_file_t *df,
		sc_pkcs15_object_t *pin_obj,
		const unsigned char *pin, size_t pin_len,
		const unsigned char *puk, size_t puk_len)
{
	struct sc_card *card = p15card->card;
	sc_pkcs15_auth_info_t *auth_info = (sc_pkcs15_auth_info_t *) pin_obj->data;
	struct sc_pkcs15_pin_attributes *pin_attrs = &auth_info->attrs.pin;
	struct sc_pin_cmd_data data;
	int r;

	LOG_FUNC_CALLED(card->ctx);

	if (auth_info->auth_type != SC_PKCS15_PIN_AUTH_TYPE_PIN)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_OBJECT_NOT_VALID);
	if (pin_attrs->reference != JCOP_USER_PIN_REF &&
			pin_attrs->reference != JCOP_SO_PIN_REF)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);

	if (puk != NULL && puk_len > 0)
		sc_log(card->ctx, "The applet has no PUK, the PUK is ignored");

	if (pin == NULL || pin_len == 0)
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);

	r = sc_select_file(card, &df->path, NULL);
	LOG_TEST_RET(card->ctx, r, "Cannot select application DF");

	memset(&data, 0, sizeof data);
	data.cmd = SC_PIN_CMD_VERIFY;
	data.pin_type = SC_AC_CHV;
	data.pin_reference = pin_attrs->reference;
	data.pin1.data = pin;
	data.pin1.len = pin_len;
	data.pin1.pad_char = pin_attrs->pad_char;
	data.pin1.pad_length = pin_attrs->max_length;
	data.flags = SC_PIN_CMD_NEED_PADDING;

	r = sc_pin_cmd(card, &data);
	LOG_TEST_RET(card->ctx, r, "PIN does not match the PIN set at applet install");

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

/*
 * Create a new key file
 */
static int
jcop_create_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card, sc_pkcs15_object_t *obj)
{
        sc_pkcs15_prkey_info_t *key_info = (sc_pkcs15_prkey_info_t *) obj->data;
        sc_file_t  *keyfile = NULL;
        size_t          bytes, mod_len, prv_len;
        int             r;

        if (obj->type != SC_PKCS15_TYPE_PRKEY_RSA) {
                sc_log(p15card->card->ctx,  "JCOP supports only RSA keys.");
                return SC_ERROR_NOT_SUPPORTED;
        }
        /* The caller is supposed to have chosen a key file path for us */
        if (key_info->path.len == 0 || key_info->modulus_length == 0)
                return SC_ERROR_INVALID_ARGUMENTS;

        /* Get the file we're supposed to create */
        r = sc_profile_get_file_by_path(profile, &key_info->path, &keyfile);
        if (r < 0)
                return r;

        mod_len = key_info->modulus_length / 8;
        bytes   = mod_len / 2;
        prv_len = 2 + 5 * bytes;
        keyfile->size = prv_len;

        /* Fix up PIN references in file ACL */
        r = sc_pkcs15init_fixup_file(profile, p15card, keyfile);

        if (r >= 0)
                r = sc_pkcs15init_create_file(profile, p15card, keyfile);

        sc_file_free(keyfile);
        return r;
}

static void
jcop_bn2bin(unsigned char *dest, sc_pkcs15_bignum_t *bn, size_t size)
{
        u8              *src;
        size_t n;

        assert(bn->len <= size);
        memset(dest, 0, size);
        for (n = size-bn->len, src = bn->data; n < size; n++,src++)
                dest[n] = *src;
}

/*
 * Store a private key
 * Private key file formats: (transparent file)
 * Non-CRT:
 * byte 0     0x05
 * byte 1     Modulus length (in byte/4)
 * byte 2     Modulus (n)
 * byte 2+x   private exponent (d)
 *
 * CRT:
 * byte 0     0x06
 * byte 1     component length (in byte/2; component length is half
 *            of modulus length
 * byte 2     Prime (p)
 * byte 2+x   Prime (q)
 * byte 2+2*x Exponent 1 (d mod (p-1))
 * byte 2+3*x Exponent 2 (d mod (q-1))
 * byte 2+4*x Coefficient ((p ^ -1) mod q
 *
 * We use the CRT format, since that's what key generation does.
 *
 * Numbers are stored big endian.
 */
static int
jcop_store_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
                sc_pkcs15_object_t *obj,
                sc_pkcs15_prkey_t *key)
{
        sc_pkcs15_prkey_info_t *key_info = (sc_pkcs15_prkey_info_t *) obj->data;
        sc_file_t       *keyfile;
        unsigned char   keybuf[1024];
        size_t          size,base;
        int             r;

        if (obj->type != SC_PKCS15_TYPE_PRKEY_RSA) {
                sc_log(p15card->card->ctx,  "JCOP supports only RSA keys.");
                return SC_ERROR_NOT_SUPPORTED;
        }
        r = sc_profile_get_file_by_path(profile, &key_info->path, &keyfile);
        if (r < 0)
                return r;
	base=key_info->modulus_length / 16;
	size=2+5*base;
	keybuf[0]=6;
	keybuf[1]=base/4;
	jcop_bn2bin(&keybuf[2 + 0 * base], &key->u.rsa.p, base);
	jcop_bn2bin(&keybuf[2 + 1 * base], &key->u.rsa.q, base);
	jcop_bn2bin(&keybuf[2 + 2 * base], &key->u.rsa.dmp1, base);
	jcop_bn2bin(&keybuf[2 + 3 * base], &key->u.rsa.dmq1, base);
	jcop_bn2bin(&keybuf[2 + 4 * base], &key->u.rsa.iqmp, base);
        r = sc_pkcs15init_update_file(profile, p15card, keyfile, keybuf, size);

	sc_file_free(keyfile);
	return r;
}

/*
 * Generate a key pair
 */
static int
jcop_generate_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
		  sc_pkcs15_object_t *obj,
		  sc_pkcs15_pubkey_t *pubkey)
{
     sc_pkcs15_prkey_info_t *key_info = (sc_pkcs15_prkey_info_t *) obj->data;
     struct sc_cardctl_jcop_genkey args;
     sc_file_t       *temppubfile=NULL, *keyfile=NULL;
     unsigned char   *keybuf=NULL;
     size_t          mod_len, exp_len, pub_len, keybits;
     int             r,delete_ok=0;

     if (obj->type != SC_PKCS15_TYPE_PRKEY_RSA) {
	  sc_log(p15card->card->ctx,  "JCOP supports only RSA keys.");
	  return SC_ERROR_NOT_SUPPORTED;
     }

     r=sc_profile_get_file(profile, "temp-pubkey", &temppubfile);
     if (r < 0)
	  goto out;

     r = sc_select_file(p15card->card, &key_info->path, &keyfile);
     if (r < 0)
	  goto out;

     mod_len = key_info->modulus_length / 8;
     exp_len = 4;
     pub_len = 2 + mod_len + exp_len;
     temppubfile->size = pub_len;

     r = sc_pkcs15init_fixup_file(profile, p15card, temppubfile);
     if (r < 0)
	  goto out;

     r = sc_pkcs15init_create_file(profile, p15card, temppubfile);
     if (r < 0)
	  goto out;

     delete_ok=1;
     r = sc_pkcs15init_authenticate(profile, p15card, temppubfile, SC_AC_OP_UPDATE);
     if (r < 0)
	  goto out;
     r = sc_pkcs15init_authenticate(profile, p15card, keyfile, SC_AC_OP_UPDATE);
     if (r < 0)
	  goto out;

     keybits = key_info->modulus_length;

     /* generate key */
     /* keysize is _not_ passed to the card at any point. it appears to
	infer it from the file size */
     memset(&args, 0, sizeof(args));
     args.exponent = 0x10001;
     sc_append_file_id(&args.pub_file_ref, temppubfile->id);
     sc_append_file_id(&args.pri_file_ref, keyfile->id);
     keybuf = malloc(keybits / 8);
     if (!keybuf) {
	  r=SC_ERROR_OUT_OF_MEMORY;
	  goto out;
     }
     args.pubkey = keybuf;
     args.pubkey_len = keybits / 8;

     r = sc_card_ctl(p15card->card, SC_CARDCTL_JCOP_GENERATE_KEY, (void *)&args);
     if (r < 0)
	  goto out;

     /* extract public key */
     pubkey->algorithm = SC_ALGORITHM_RSA;
     pubkey->u.rsa.modulus.len   = keybits / 8;
     pubkey->u.rsa.modulus.data  = keybuf;
     pubkey->u.rsa.exponent.len  = 3;
     pubkey->u.rsa.exponent.data = malloc(3);
     if (!pubkey->u.rsa.exponent.data) {
	  pubkey->u.rsa.modulus.data = NULL;
	  r=SC_ERROR_OUT_OF_MEMORY;
	  goto out;
     }
     memcpy(pubkey->u.rsa.exponent.data, "\x01\x00\x01", 3);

 out:
     if (r < 0 && keybuf)
	  free(keybuf);
     if (delete_ok)
	  sc_pkcs15init_rmdir(p15card, profile, temppubfile);
	 sc_file_free(keyfile);
	 sc_file_free(temppubfile);
     return r;
}



/*
 * Middleware may cache the card contents and check EF 6378 in
 * the application DF, which has the layout of the minidriver cardcf file:
 * version, PIN freshness, containers freshness and files freshness, the
 * last two as 16 bit little endian counters. Increment the counters, so
 * that it notices changes.
 */
#define JCOP4_CARDCF_FID	0x6378

static int
jcop4_update_cardcf(sc_pkcs15_card_t *p15card, int containers, int files)
{
	struct sc_context *ctx = p15card->card->ctx;
	struct sc_path path;
	u8 buf[6];
	unsigned int n;
	int r;

	LOG_FUNC_CALLED(ctx);

	if (p15card->file_app == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INTERNAL);
	path = p15card->file_app->path;
	r = sc_append_file_id(&path, JCOP4_CARDCF_FID);
	LOG_TEST_RET(ctx, r, "Cannot build cardcf path");

	r = sc_select_file(p15card->card, &path, NULL);
	if (r == SC_ERROR_FILE_NOT_FOUND)
		LOG_FUNC_RETURN(ctx, SC_SUCCESS);
	LOG_TEST_RET(ctx, r, "Cannot select cardcf");

	r = sc_read_binary(p15card->card, 0, buf, sizeof(buf), 0);
	LOG_TEST_RET(ctx, r, "Cannot read cardcf");
	if (r != sizeof(buf))
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Unexpected cardcf length");

	if (containers) {
		n = (buf[2] | (buf[3] << 8)) + 1;
		buf[2] = n & 0xFF;
		buf[3] = (n >> 8) & 0xFF;
	}
	if (files) {
		n = (buf[4] | (buf[5] << 8)) + 1;
		buf[4] = n & 0xFF;
		buf[5] = (n >> 8) & 0xFF;
	}
	r = sc_update_binary(p15card->card, 0, buf, sizeof(buf), 0);
	LOG_TEST_RET(ctx, r, "Cannot update cardcf");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

/*
 * Private keys are key objects in the application DF, addressed by
 * key reference only. The range depends on the applet variant.
 */
static int
jcop4_get_key_layout(sc_pkcs15_card_t *p15card, struct sc_cardctl_jcop4_key_layout *layout)
{
	memset(layout, 0, sizeof(*layout));
	return sc_card_ctl(p15card->card, SC_CARDCTL_JCOP4_GET_KEY_LAYOUT, layout);
}

static int
jcop4_select_key_reference(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
		sc_pkcs15_prkey_info_t *key_info)
{
	struct sc_cardctl_jcop4_key_layout layout;
	int r;

	r = jcop4_get_key_layout(p15card, &layout);
	LOG_TEST_RET(p15card->card->ctx, r, "Cannot get key layout");

	if (key_info->key_reference < layout.key_ref_min)
		key_info->key_reference = layout.key_ref_min;
	if (key_info->key_reference > layout.key_ref_max)
		return SC_ERROR_TOO_MANY_OBJECTS;
	return SC_SUCCESS;
}

/*
 * Create the key object. Its size is the key length in bits.
 */
static int
jcop4_create_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card, sc_pkcs15_object_t *obj)
{
	struct sc_context *ctx = p15card->card->ctx;
	sc_pkcs15_prkey_info_t *key_info = (sc_pkcs15_prkey_info_t *) obj->data;
	struct sc_pkcs15_object *pin_obj = NULL;
	struct sc_pkcs15_auth_info *auth_info;
	sc_file_t *keyfile = NULL;
	int r;

	LOG_FUNC_CALLED(ctx);

	if (obj->type != SC_PKCS15_TYPE_PRKEY_RSA)
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "JCOP supports only RSA keys.");
	if (key_info->modulus_length == 0 || key_info->modulus_length > 0xFFFF)
		LOG_FUNC_RETURN(ctx, SC_ERROR_INVALID_ARGUMENTS);

	r = sc_pkcs15_find_pin_by_auth_id(p15card, &obj->auth_id, &pin_obj);
	LOG_TEST_RET(ctx, r, "Cannot find PIN of the private key");
	auth_info = (struct sc_pkcs15_auth_info *) pin_obj->data;

	keyfile = sc_file_new();
	if (keyfile == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	keyfile->type = SC_FILE_TYPE_INTERNAL_EF;
	keyfile->id = key_info->key_reference;
	keyfile->size = key_info->modulus_length;
	sc_file_add_acl_entry(keyfile, SC_AC_OP_CRYPTO, SC_AC_CHV, auth_info->attrs.pin.reference);
	sc_file_add_acl_entry(keyfile, SC_AC_OP_GENERATE, SC_AC_CHV, auth_info->attrs.pin.reference);

	/* key objects cannot be selected, authenticate with the path of the DF */
	keyfile->path = key_info->path;
	r = sc_pkcs15init_authenticate(profile, p15card, keyfile, SC_AC_OP_GENERATE);
	LOG_TEST_GOTO_ERR(ctx, r, "Authentication failed");

	r = jcop4_update_cardcf(p15card, 1, 0);
	LOG_TEST_GOTO_ERR(ctx, r, "Cannot update cardcf");

	r = sc_append_file_id(&keyfile->path, keyfile->id);
	LOG_TEST_GOTO_ERR(ctx, r, "Cannot build key path");
	r = sc_pkcs15init_create_file(profile, p15card, keyfile);
	LOG_TEST_GOTO_ERR(ctx, r, "Cannot create key object");

err:
	sc_file_free(keyfile);
	LOG_FUNC_RETURN(ctx, r);
}

static int
jcop4_store_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
		sc_pkcs15_object_t *obj, sc_pkcs15_prkey_t *key)
{
	return SC_ERROR_NOT_SUPPORTED;
}

/*
 * Generate a key pair in the key object created by jcop4_create_key()
 */
static int
jcop4_generate_key(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
		sc_pkcs15_object_t *obj, sc_pkcs15_pubkey_t *pubkey)
{
	struct sc_context *ctx = p15card->card->ctx;
	sc_pkcs15_prkey_info_t *key_info = (sc_pkcs15_prkey_info_t *) obj->data;
	struct sc_cardctl_jcop4_genkey args;
	int r;

	LOG_FUNC_CALLED(ctx);

	if (obj->type != SC_PKCS15_TYPE_PRKEY_RSA)
		LOG_TEST_RET(ctx, SC_ERROR_NOT_SUPPORTED, "JCOP supports only RSA keys.");

	memset(&args, 0, sizeof(args));
	args.key_bits = key_info->modulus_length;
	r = sc_card_ctl(p15card->card, SC_CARDCTL_JCOP4_GENERATE_KEY, &args);
	LOG_TEST_RET(ctx, r, "Key generation failed");

	pubkey->algorithm = SC_ALGORITHM_RSA;
	r = sc_pkcs15_decode_pubkey_rsa(ctx, &pubkey->u.rsa, args.pubkey, args.pubkey_len);
	free(args.pubkey);
	LOG_TEST_RET(ctx, r, "Cannot decode public key");

	if (pubkey->u.rsa.modulus.len * 8 != key_info->modulus_length)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_DATA, "Unexpected modulus length");

	LOG_FUNC_RETURN(ctx, SC_SUCCESS);
}

/*
 * Delete the key object of a private key. Other objects are stored in
 * EFs and deleted by the generic code.
 */
static int
jcop4_delete_object(sc_profile_t *profile, sc_pkcs15_card_t *p15card,
		sc_pkcs15_object_t *obj, const struct sc_path *path)
{
	struct sc_context *ctx = p15card->card->ctx;
	sc_pkcs15_prkey_info_t *key_info;
	struct sc_pkcs15_object *pin_obj = NULL;
	struct sc_pkcs15_auth_info *auth_info;
	struct sc_cardctl_jcop4_key_layout layout;
	struct sc_path key_path;
	sc_file_t *keyfile = NULL;
	int r;

	LOG_FUNC_CALLED(ctx);

	if ((obj->type & SC_PKCS15_TYPE_CLASS_MASK) != SC_PKCS15_TYPE_PRKEY) {
		r = jcop4_update_cardcf(p15card, 0, 1);
		LOG_TEST_RET(ctx, r, "Cannot update cardcf");
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_SUPPORTED);
	}
	key_info = (sc_pkcs15_prkey_info_t *) obj->data;
	r = jcop4_get_key_layout(p15card, &layout);
	LOG_TEST_RET(ctx, r, "Cannot get key layout");
	if (key_info->key_reference < layout.key_ref_min || key_info->key_reference > layout.key_ref_max)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid key reference");

	r = sc_pkcs15_find_pin_by_auth_id(p15card, &obj->auth_id, &pin_obj);
	LOG_TEST_RET(ctx, r, "Cannot find PIN of the private key");
	auth_info = (struct sc_pkcs15_auth_info *) pin_obj->data;

	keyfile = sc_file_new();
	if (keyfile == NULL)
		LOG_FUNC_RETURN(ctx, SC_ERROR_OUT_OF_MEMORY);
	keyfile->path = key_info->path;
	sc_file_add_acl_entry(keyfile, SC_AC_OP_DELETE, SC_AC_CHV, auth_info->attrs.pin.reference);
	r = sc_pkcs15init_authenticate(profile, p15card, keyfile, SC_AC_OP_DELETE);
	sc_file_free(keyfile);
	LOG_TEST_RET(ctx, r, "Authentication failed");

	r = jcop4_update_cardcf(p15card, 1, 0);
	LOG_TEST_RET(ctx, r, "Cannot update cardcf");

	memset(&key_path, 0, sizeof(key_path));
	key_path.type = SC_PATH_TYPE_FILE_ID;
	key_path.value[0] = 0x00;
	key_path.value[1] = key_info->key_reference & 0xFF;
	key_path.len = 2;
	r = sc_delete_file(p15card->card, &key_path);
	LOG_TEST_RET(ctx, r, "Cannot delete key object");

	LOG_FUNC_RETURN(ctx, r);
}

/*
 * On applet variant 2 the public key of a key pair is stored in the EF
 * 00<key reference + offset>, with the ACLs of the profile template.
 */
static int
jcop4_store_public_key(sc_pkcs15_card_t *p15card, sc_profile_t *profile,
		sc_pkcs15_object_t *obj, struct sc_pkcs15_der *data, struct sc_path *path,
		int fid_offset)
{
	struct sc_context *ctx = p15card->card->ctx;
	sc_pkcs15_pubkey_info_t *pubkey_info = (sc_pkcs15_pubkey_info_t *) obj->data;
	sc_pkcs15_object_t *prkey_obj = NULL;
	sc_pkcs15_prkey_info_t *prkey_info;
	sc_file_t *file = NULL;
	int r, fid;

	LOG_FUNC_CALLED(ctx);

	r = sc_pkcs15_find_prkey_by_id(p15card, &pubkey_info->id, &prkey_obj);
	if (r == SC_ERROR_OBJECT_NOT_FOUND)
		LOG_FUNC_RETURN(ctx, SC_ERROR_NOT_IMPLEMENTED);
	LOG_TEST_RET(ctx, r, "Cannot find the private key");
	prkey_info = (sc_pkcs15_prkey_info_t *) prkey_obj->data;
	fid = prkey_info->key_reference + fid_offset;
	if (fid > 0xFF)
		LOG_TEST_RET(ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid key reference");

	r = sc_profile_get_file(profile, "template-public-key", &file);
	LOG_TEST_RET(ctx, r, "No public key template in the profile");
	file->id = fid;
	file->size = data->len;
	file->path = p15card->file_app->path;
	r = sc_append_file_id(&file->path, fid);
	LOG_TEST_GOTO_ERR(ctx, r, "Cannot build public key path");

	r = sc_pkcs15init_delete_by_path(profile, p15card, &file->path);
	if (r != SC_ERROR_FILE_NOT_FOUND)
		LOG_TEST_GOTO_ERR(ctx, r, "Cannot delete public key file");
	r = sc_pkcs15init_update_file(profile, p15card, file, data->value, data->len);
	LOG_TEST_GOTO_ERR(ctx, r, "Cannot store public key");

	*path = file->path;
err:
	sc_file_free(file);
	LOG_FUNC_RETURN(ctx, r);
}

/*
 * Called before the generic code stores an object in an EF
 */
static int
jcop4_emu_store_data(sc_pkcs15_card_t *p15card, sc_profile_t *profile,
		sc_pkcs15_object_t *obj, struct sc_pkcs15_der *data, struct sc_path *path)
{
	struct sc_cardctl_jcop4_key_layout layout;
	int r;

	if (data == NULL)
		return SC_ERROR_NOT_IMPLEMENTED;

	r = jcop4_update_cardcf(p15card, 0, 1);
	LOG_TEST_RET(p15card->card->ctx, r, "Cannot update cardcf");

	if ((obj->type & SC_PKCS15_TYPE_CLASS_MASK) == SC_PKCS15_TYPE_PUBKEY &&
			p15card->file_app != NULL &&
			jcop4_get_key_layout(p15card, &layout) == SC_SUCCESS &&
			layout.pubkey_fid_offset)
		return jcop4_store_public_key(p15card, profile, obj, data, path,
				layout.pubkey_fid_offset);

	return SC_ERROR_NOT_IMPLEMENTED;
}

/*
 * The card has no EF(DIR), the application is selected by its AID.
 */
static int
jcop4_emu_update_dir(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		struct sc_app_info *app)
{
	sc_log(p15card->card->ctx, "No EF(DIR) on this card, skipped");
	return SC_SUCCESS;
}

/*
 * Write one object as record rec_nr of a linear variable TLV record EF.
 * The record holds a simple TLV: [record number] [length] [DER object],
 * an empty record is 00 00.
 */
static int
jcop4_write_df_record(struct sc_card *card, unsigned int rec_nr,
		const u8 *obj, size_t obj_len, size_t max_rec_len)
{
	u8 rec[SC_MAX_APDU_BUFFER_SIZE];
	size_t len = 0;

	if (obj_len > 0) {
		if (obj_len < 0xFF) {
			rec[len++] = (u8)rec_nr;
			rec[len++] = (u8)obj_len;
		} else {
			rec[len++] = (u8)rec_nr;
			rec[len++] = 0xFF;
			rec[len++] = (obj_len >> 8) & 0xFF;
			rec[len++] = obj_len & 0xFF;
		}
	} else {
		rec[len++] = 0x00;
		rec[len++] = 0x00;
	}
	if (len + obj_len > max_rec_len || len + obj_len > sizeof rec)
		return SC_ERROR_FILE_TOO_SMALL;
	if (obj_len)
		memcpy(rec + len, obj, obj_len);
	len += obj_len;

	return sc_update_record(card, rec_nr, 0, rec, len, SC_RECORD_BY_REC_NR);
}

/*
 * The applet keeps the AODF and some other DFs in linear variable TLV
 * record EFs, one object per record. pkcs15init writes a DF with one
 * UPDATE BINARY, which the card rejects for record EFs. Rewrite all
 * records of such a DF instead; other DFs are written the normal way.
 */
static int
jcop4_emu_update_any_df(struct sc_profile *profile, struct sc_pkcs15_card *p15card,
		unsigned op, struct sc_pkcs15_object *object)
{
	struct sc_card *card = p15card->card;
	struct sc_pkcs15_df *df = object ? object->df : NULL;
	struct sc_pkcs15_object *o;
	struct sc_file *file = NULL;
	unsigned char *buf = NULL;
	const u8 *p, *obj;
	size_t buflen = 0, left, obj_len, skip = 0, n;
	unsigned int cla_out, tag_out, rec_nr = 1;
	int r;

	LOG_FUNC_CALLED(card->ctx);
	if (df == NULL)
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);

	r = sc_select_file(card, &df->path, &file);
	LOG_TEST_RET(card->ctx, r, "Cannot select DF");

	if (file->ef_structure != SC_FILE_EF_LINEAR_VARIABLE_TLV) {
		sc_file_free(file);
		/* the object is removed from the DF after this call */
		if (op == SC_AC_OP_ERASE)
			LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
		r = sc_pkcs15init_update_any_df(p15card, profile, df, 0);
		LOG_FUNC_RETURN(card->ctx, r);
	}

	/* the object to erase is still part of the DF, find its position */
	if (op == SC_AC_OP_ERASE) {
		for (o = p15card->obj_list, n = 1; o != NULL; o = o->next) {
			if (o->df != df)
				continue;
			if (o == object) {
				skip = n;
				break;
			}
			n++;
		}
	}

	r = sc_pkcs15init_authenticate(profile, p15card, file, SC_AC_OP_UPDATE);
	LOG_TEST_GOTO_ERR(card->ctx, r, "Cannot authenticate for DF update");

	r = sc_pkcs15_encode_df(card->ctx, p15card, df, &buf, &buflen);
	LOG_TEST_GOTO_ERR(card->ctx, r, "Cannot encode DF");

	p = buf;
	left = buflen;
	for (n = 1; left > 0 && *p != 0x00 && *p != 0xFF; n++) {
		obj = p;
		r = sc_asn1_read_tag(&p, left, &cla_out, &tag_out, &obj_len);
		if (r != SC_SUCCESS || p == NULL) {
			r = SC_ERROR_INVALID_DATA;
			LOG_TEST_GOTO_ERR(card->ctx, r, "Cannot split DF into objects");
		}
		obj_len += p - obj;
		p = obj + obj_len;
		left -= obj_len;
		if (n == skip)
			continue;

		if (rec_nr > file->record_count) {
			r = SC_ERROR_FILE_TOO_SMALL;
			LOG_TEST_GOTO_ERR(card->ctx, r, "No free record in DF");
		}
		r = jcop4_write_df_record(card, rec_nr, obj, obj_len, file->record_length);
		LOG_TEST_GOTO_ERR(card->ctx, r, "Cannot write object record");
		rec_nr++;
	}

	/* clear the records of objects that are gone */
	for (; rec_nr <= file->record_count; rec_nr++) {
		r = jcop4_write_df_record(card, rec_nr, NULL, 0, file->record_length);
		LOG_TEST_GOTO_ERR(card->ctx, r, "Cannot clear record");
	}
	r = SC_SUCCESS;

err:
	free(buf);
	sc_file_free(file);
	LOG_FUNC_RETURN(card->ctx, r);
}

static struct sc_pkcs15init_operations sc_pkcs15init_jcop_operations = {
	jcop_erase_card,
	NULL,				/* init_card     */
	jcop_create_dir,
	NULL,				/* create_domain */
	jcop_select_pin_reference,
	jcop_create_pin,
	jcop4_select_key_reference,
	jcop4_create_key,
	jcop4_store_key,
	jcop4_generate_key,
	NULL, NULL,			/* encode private/public key */
	NULL,				/* finalize_card */
	jcop4_delete_object,
	jcop4_emu_update_dir,
	jcop4_emu_update_any_df,
	NULL, NULL,			/* emu_update_tokeninfo, emu_write_info */
	jcop4_emu_store_data,
	NULL				/* sanity_check */
};

struct sc_pkcs15init_operations *sc_pkcs15init_get_jcop_ops(void)
{
     return &sc_pkcs15init_jcop_operations;
}



/*
 * card-jcop.c
 *
 * Copyright (C) 2003 Chaskiel Grundman <cg2v@andrew.cmu.edu>
 * Copyright (C) 2026 Martin Vogt <mvogt1@gmail.com>
 * 
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


/**
  * A copy of the manual can be found here (Rev 2.01, 30/06/2003):
  * 
  * [1] https://public.dhe.ibm.com/software/pervasive/info/BlueZ-PKCS15.pdf
  * 
  */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "internal.h"
#include "cardctl.h"
#include <string.h>
#include <stdlib.h>

static struct sc_card_operations jcop_ops;
static struct sc_card_driver jcop_drv = {
     "JCOP cards with BlueZ PKCS#15 applet",
     "jcop",
     &jcop_ops,
     NULL, 0, NULL
};
#define SELECT_MF 0
#define SELECT_EFDIR 1
#define SELECT_APPDF 2
#define SELECT_EF 3
#define SELECT_UNKNOWN 4

typedef struct jcop_private_data_s 
{
     struct sc_file *virtmf;

     int selected;
     int invalid_senv;
     size_t nfiles;
     u8 *filelist;

     int key_ref;
     int algorithm_flags;
     int algorithm;
} jcop_private_data_t ;
#define DRVDATA(card)   ((jcop_private_data_t *) ((card)->drv_data))

static int jcop_finish(struct sc_card *card)
{
     jcop_private_data_t *drvdata=DRVDATA(card);
     
     if (drvdata) {
	  sc_file_free(drvdata->virtmf);
	  

	  free(drvdata);
	  card->drv_data=NULL;
     }
     
     return 0;
}

static const unsigned char jcop_aid[] = {
		0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35 };

static const struct sc_card_operations *iso_ops = NULL;

static const struct sc_atr_table jcop_atrs[] = {
       { "3B:E6:00:FF:81:31:FE:45:4A:43:4F:50:33:31:06", NULL, "jcop 2.x", SC_CARD_TYPE_JCOP_GENERIC, 0, NULL },
       { "3B:F9:96:00:00:80:31:FE:45:53:43:45:37:20:00:00:20:20:27", NULL, "jcop 4.x", SC_CARD_TYPE_JCOP_V4_7, 0, NULL },
       { NULL, NULL, NULL, 0, 0, NULL }
};


static int jcop_match_card(struct sc_card *card)
{
    int i;
    printf("JCOP4 \n");
    i = _sc_match_atr(card, jcop_atrs, &card->type);
    if (i < 0)
       return 0;
    card->name = jcop_atrs[i].name; 
    printf("JCOP4 OK\n");
    return 1; 
}


static sc_file_t* jcop_get_mf()
{
	static sc_file_t *mf = NULL;
	if (!mf) {
		mf = sc_file_new();
		if (mf) {
			mf->path = *sc_get_mf_path();
			mf->id = 0x3F00;
			mf->type = SC_FILE_TYPE_DF;
			mf->magic = SC_FILE_MAGIC;
		}
	}
	return mf;
}


static int jcop_init(struct sc_card *card)
{
     jcop_private_data_t *drvdata;
     unsigned long flags;
     int r;

     LOG_FUNC_CALLED(card->ctx);
     r = iso7816_select_aid(card,jcop_aid, sizeof(jcop_aid), NULL, NULL);
	LOG_TEST_RET(card->ctx, r, "Cannot select JCOP application");


     drvdata=malloc(sizeof(jcop_private_data_t));
     if (!drvdata)
	  return SC_ERROR_OUT_OF_MEMORY;
     memset(drvdata, 0, sizeof(jcop_private_data_t));

     drvdata->virtmf=jcop_get_mf();
     if (!drvdata->virtmf) {
          jcop_finish(card);
          return SC_ERROR_OUT_OF_MEMORY;
     }
     
     
     card->drv_data = drvdata;
     card->cla = 0x00;

     /* card supports host-side padding, but not raw rsa */
     //flags = SC_ALGORITHM_RSA_PAD_PKCS1;
     flags = SC_ALGORITHM_RSA_PAD_NONE;
     flags |= SC_ALGORITHM_RSA_HASH_NONE;
     //flags |= SC_ALGORITHM_RSA_HASH_SHA1;
     //flags |= SC_ALGORITHM_RSA_HASH_MD5;
     /* only supports keygen with 3 and F-4  exponents */
     flags |= SC_ALGORITHM_ONBOARD_KEY_GEN;
     _sc_card_add_rsa_alg(card, 512, flags, 0);
     _sc_card_add_rsa_alg(card, 768, flags, 0);
     _sc_card_add_rsa_alg(card, 1024, flags, 0);
     _sc_card_add_rsa_alg(card, 2048, flags, 0);
     /* State that we have an RNG */
     card->caps |= SC_CARD_CAP_RNG;
     // Javacard support extended APDU
     card->caps |= SC_CARD_CAP_APDU_EXT;

     //card->max_send_size = 255;
	//card->max_recv_size = 256;

     //exit(0);
     LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}

static int jcop_get_default_key(struct sc_card *card,
                                struct sc_cardctl_default_key *data)
{
	const char *key;

	if (data->method != SC_AC_PRO || data->key_ref > 2)
		return SC_ERROR_NO_DEFAULT_KEY;

	key = "40:41:42:43:44:45:46:47:48:49:4A:4B:4C:4D:4E:4F";
	return sc_hex_to_bin(key, data->key_data, &data->len);
}




static int jcop4_select_file(struct sc_card *card, const struct sc_path *in_path,
		struct sc_file **file_out)
{
	struct sc_path path = *in_path;
     jcop_private_data_t *drvdata=DRVDATA(card);

	LOG_FUNC_CALLED(card->ctx);
	if (path.aid.len == sizeof jcop_aid && 0 == memcmp(path.aid.value, jcop_aid, sizeof jcop_aid)) {
		path.aid.len = 0;
          drvdata->selected = SELECT_APPDF;
	}
     if (path.type == SC_PATH_TYPE_PATH && 
          (path.len >= 4 && (0 == memcmp(path.value, "\x3F\x00\x2F\x00", 4) ) ) ) {
		memmove(path.value, path.value + 4, path.len - 4);
		path.len -= 4;
          drvdata->selected = SELECT_EFDIR;
	}
     if (path.type == SC_PATH_TYPE_PATH && 
          (path.len >= 4 && (0 == memcmp(path.value, "\x3F\x00\x50\x15", 4) ) ) ) {
		memmove(path.value, path.value + 4, path.len - 4);
		path.len -= 4;
          drvdata->selected = SELECT_APPDF;
	}
	if (path.type == SC_PATH_TYPE_PATH && 
          (path.len >= 2 && (0 == memcmp(path.value, "\x3F\x00", 2) ) ) ) {
		memmove(path.value, path.value + 2, path.len - 2);
		path.len -= 2;
          drvdata->selected=SELECT_MF;
	}
	if (path.type == SC_PATH_TYPE_PATH && path.len == 0) {
		/* Selection of MF was requested */
		sc_file_dup(file_out, jcop_get_mf());
		LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
	}
     drvdata->selected=SELECT_EF;
	LOG_FUNC_RETURN(card->ctx, iso_ops->select_file(card, &path, file_out));
}

static int sa_to_acl(struct sc_file *file, unsigned int operation, 
		     int nibble) {
     switch (nibble & 0x7) {
     case 0:
	  sc_file_add_acl_entry(file, operation, SC_AC_NONE, SC_AC_KEY_REF_NONE);
	  break;
     case 1:
	  sc_file_add_acl_entry(file, operation, SC_AC_NEVER, SC_AC_KEY_REF_NONE);
	  break;
     case 2:
	  sc_file_add_acl_entry(file, operation, SC_AC_CHV, 1);
	  break;
     case 3:
	  sc_file_add_acl_entry(file, operation, SC_AC_CHV, 2);
	  break;
     case 4:
	  sc_file_add_acl_entry(file, operation, SC_AC_CHV, 3);
	  break;
     case 5:
	  sc_file_add_acl_entry(file, operation, SC_AC_AUT, SC_AC_KEY_REF_NONE);
	  break;
     case 6:
	  sc_file_add_acl_entry(file, operation, SC_AC_PRO, SC_AC_KEY_REF_NONE);
	  break;
     default:
	  sc_file_add_acl_entry(file, operation, SC_AC_UNKNOWN, SC_AC_KEY_REF_NONE);
     }
     return 0;
}


static int jcop_process_fci(struct sc_card *card, struct sc_file *file,
			    const u8 *buf, size_t buflen) {
     jcop_private_data_t *drvdata=DRVDATA(card);
     struct sc_card_driver *iso_drv = sc_get_iso7816_driver();
     const struct sc_card_operations *iso_ops = iso_drv->ops;
     u8 *sa;
     int r;

     /* the FCI for EF's includes a bogus length for the overall structure!  */
     if (buflen == 19)
       buflen=24;
     r=iso_ops->process_fci(card, file, buf, buflen);
     
     if (r < 0)
	  return r;
     if (file->type != SC_FILE_TYPE_DF) {
	  if (drvdata->nfiles) {
	       drvdata->nfiles=-1;
	       free(drvdata->filelist);
	       drvdata->filelist=0;
	  }
	  if(file->sec_attr_len >=3) {
	       /* The security attribute bytes are divided into nibbles and are
		  as follows:
		  READ | MODIFY || SIGN | ENCIPHER || DECIPHER | DELETE 
	       */
	       sa=file->sec_attr;
	       sa_to_acl(file, SC_AC_OP_READ, sa[0] >> 4);
	       sa_to_acl(file, SC_AC_OP_UPDATE, sa[0] & 0xf);
	       /* Files may be locked by anyone who can MODIFY. */
	       /* opensc seems to think LOCK ACs are only on DFs */
	       /* sa_to_acl(file, SC_AC_OP_LOCK, sa[0] & 0xf); */
	       /* there are seperate SIGN, ENCIPHER, and DECIPHER ACs.
		  I use SIGN for SC_AC_OP_CRYPTO unless it is NEVER, in 
		  which case I use DECIPHER */
	       if ((sa[1] & 0xf0) == 0x10)
		    sa_to_acl(file, SC_AC_OP_CRYPTO, sa[1] >> 4);
	       else
		    sa_to_acl(file, SC_AC_OP_CRYPTO, sa[2] >> 4);
	       sa_to_acl(file, SC_AC_OP_ERASE, sa[2] & 0xf);
	  }
     } else {
	  /* No AC information is reported for the AppDF */
	  sc_file_add_acl_entry(file, SC_AC_OP_SELECT, SC_AC_NONE, 0);
	  sc_file_add_acl_entry(file, SC_AC_OP_CREATE, SC_AC_CHV, 3);
	  sc_file_add_acl_entry(file, SC_AC_OP_DELETE, SC_AC_NONE, 0);
	  sc_file_add_acl_entry(file, SC_AC_OP_LIST_FILES, SC_AC_NONE, 0);
	  if (drvdata->nfiles) {
	       drvdata->nfiles=0;
	       free(drvdata->filelist);
	       drvdata->filelist=0;
	  }    
	  /* the format of the poprietary attributes is:
	     4 bytes     unique id
	     1 byte      # files in DF
	     2 bytes     1st File ID
	     2 bytes     2nd File ID
	     ...
	  */
	  if (file->prop_attr_len > 4) {
	       int nfiles;
	       u8 *filelist;
	       nfiles=file->prop_attr[4];
	       if (nfiles) {
		    filelist=malloc(2*nfiles);
		    if (!filelist)
			 return SC_ERROR_OUT_OF_MEMORY;
		    memcpy(filelist, &file->prop_attr[5], 2*nfiles);
		    drvdata->nfiles=nfiles;
		    drvdata->filelist=filelist;
	       }
	  }
     }
     
     return r;
}
static int acl_to_ac_nibble(const struct sc_acl_entry *e)
{
        if (e == NULL)
                return -1;
        if (e->next != NULL)    /* FIXME */
                return -1;
        switch (e->method) {
        case SC_AC_NONE:
                return 0x00;
        case SC_AC_NEVER:
                return 0x01;
        case SC_AC_CHV:
                switch (e->key_ref) {
                case 1:
                        return 0x02;
                case 2:
                        return 0x03;
                case 3:
                        return 0x04;
                }
                return -1;
        case SC_AC_AUT:
                return 0x05;
        case SC_AC_PRO:
                return 0x06;
        }
        return -1;
}


static int jcop_create_file(struct sc_card *card, struct sc_file *file) {
     jcop_private_data_t *drvdata=DRVDATA(card);
     unsigned char sec_attr_data[3];
     int ops[6];
     int i, r;
     struct sc_card_driver *iso_drv = sc_get_iso7816_driver();
     const struct sc_card_operations *iso_ops = iso_drv->ops;
     
     if (drvdata->selected == SELECT_MF || drvdata->selected == SELECT_EFDIR )
	  return sc_check_sw(card, 0x69, 0x82);
     
     /* Can't create DFs */
     if (file->type != SC_FILE_TYPE_WORKING_EF)
	  return sc_check_sw(card, 0x6A, 0x80);
     
     ops[0] = SC_AC_OP_READ;      /* read */
     ops[1] = SC_AC_OP_UPDATE;    /* modify */
     ops[2] = SC_AC_OP_CRYPTO;    /* sign */
     ops[3] = -1;                 /* encipher */
     ops[4] = SC_AC_OP_CRYPTO;    /* decipher */
     ops[5] = SC_AC_OP_ERASE;     /* delete */
     memset(sec_attr_data, 0, 3);
     for (i = 0; i < 6; i++) {
	  const struct sc_acl_entry *entry;
	  if (ops[i] == -1) {
	       sec_attr_data[i/2] |= 1 << ((i % 2) ? 0 : 4);
	       continue;
	  }
	  
	  entry = sc_file_get_acl_entry(file, ops[i]);
	  r = acl_to_ac_nibble(entry);
	  sec_attr_data[i/2] |= r << ((i % 2) ? 0 : 4);
     }

     sc_file_set_sec_attr(file, sec_attr_data, 3);
     
     r=iso_ops->create_file(card, file);
     if (r > 0)
          drvdata->selected=SELECT_EF;
     return r;
}



/* We need to trap these functions so that proper errors can be returned
   when one of the virtual files is selected */
static int jcop_write_binary(struct sc_card *card,
			unsigned int idx, const u8 *buf,
			size_t count, unsigned long flags) {
     jcop_private_data_t *drvdata=DRVDATA(card);
     struct sc_card_driver *iso_drv = sc_get_iso7816_driver();
     const struct sc_card_operations *iso_ops = iso_drv->ops;

     if (drvdata->selected == SELECT_MF)
	       return sc_check_sw(card, 0x6A, 0x86);
     if (drvdata->selected == SELECT_EFDIR)
	       return sc_check_sw(card, 0x69, 0x82);

     return iso_ops->write_binary(card, idx, buf, count, flags);
}


static int jcop_update_binary(struct sc_card *card,
			 unsigned int idx, const u8 *buf,
			 size_t count, unsigned long flags) {
     
     jcop_private_data_t *drvdata=DRVDATA(card);
     struct sc_card_driver *iso_drv = sc_get_iso7816_driver();
     const struct sc_card_operations *iso_ops = iso_drv->ops;
     if (drvdata->selected == SELECT_MF)
	       return sc_check_sw(card, 0x69, 0x86);
     if (drvdata->selected == SELECT_EFDIR)
	       return sc_check_sw(card, 0x69, 0x82);

     return iso_ops->update_binary(card, idx, buf, count, flags);
}

static int jcop_delete_file(struct sc_card *card, const struct sc_path *path) {
     jcop_private_data_t *drvdata=DRVDATA(card);
     struct sc_card_driver *iso_drv = sc_get_iso7816_driver();
     const struct sc_card_operations *iso_ops = iso_drv->ops;

     if (drvdata->selected == SELECT_MF || drvdata->selected == SELECT_EFDIR )
          return sc_check_sw(card, 0x69, 0x82);

     return iso_ops->delete_file(card, path);
}


static int jcop4_set_security_env(sc_card_t *card,
                                    const sc_security_env_t *env_in,
                                    int se_num)
{
	struct sc_card_driver *iso_drv = sc_get_iso7816_driver();
     const struct sc_card_operations *iso_ops = iso_drv->ops;

     struct sc_apdu apdu;
	u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
	u8 *p;
	int r;
	struct sc_context *ctx = card->ctx;
     // make copy of env, becaue we change it for SC_SEC_ENV_ALG_REF_PRESENT
     struct sc_security_env env_tmp=*env_in;
     struct sc_security_env* env=&env_tmp;

	jcop_private_data_t *drvdata = DRVDATA(card);

	assert(card != NULL && env != NULL);

	LOG_FUNC_CALLED(ctx);
	//printf("jcop_set_security_env\n");
	// exit(1);
     //r=myeid_set_security_env(card,env,se_num);
     //return r;
     drvdata->key_ref=-1;
     if (env->flags & SC_SEC_ENV_KEY_REF_PRESENT && env->operation != SC_SEC_OPERATION_UNWRAP &&
			env->operation != SC_SEC_OPERATION_WRAP &&
			env->operation != SC_SEC_OPERATION_ENCRYPT_SYM &&
			env->operation != SC_SEC_OPERATION_DECRYPT_SYM) {
          drvdata->key_ref=env->key_ref[0] & 0xFF;
		//printf("Storing key id:%d 0x%x\n",drvdata->key_ref,drvdata->key_ref);
	}

     if (env->flags & SC_SEC_ENV_ALG_PRESENT) {
          if (env->algorithm != SC_ALGORITHM_RSA) {
               sc_log(card->ctx, "ERROR: Only RSA algorithm supported.\n");
               return SC_ERROR_NOT_SUPPORTED;
          }
          env->flags |= SC_SEC_ENV_ALG_REF_PRESENT;
          env->algorithm_ref=0x0;
          if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA1)
               env->algorithm_ref |= 0x10;
          if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_MD5)
               env->algorithm_ref |= 0x20;
     }
     if (env->flags & SC_SEC_ENV_FILE_REF_PRESENT) {
          // remove it
          
          env->flags ^= SC_SEC_ENV_FILE_REF_PRESENT;
     }

     
     
     
     drvdata->algorithm=env->algorithm;
     drvdata->algorithm_flags = env->algorithm_flags;

     if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_SHA1) {
          printf("SC_ALGORITHM_RSA_HASH_SHA1\n");
          //tmp.algorithm_ref |= 0x10;
     }
          
     if (env->algorithm_flags & SC_ALGORITHM_RSA_HASH_MD5) {
          printf("SC_ALGORITHM_RSA_HASH_MD5");
          //tmp.algorithm_ref |= 0x20;
     }


     if (env->algorithm_flags & SC_ALGORITHM_RSA_PAD_PSS) {
          printf("SC_ALGORITHM_RSA_PAD_PSS \n");
     }

     if (env->flags & SC_SEC_ENV_ALG_REF_PRESENT)	{
          //printf("SC_SEC_ENV_ALG_REF_PRESENT: %ld 0x%lx\n",env->algorithm_ref & 0xFF,env->algorithm_ref & 0xFF);
          /*
		*p++ = 0x80;	// algorithm reference 
		*p++ = 0x01;
		*p++ = env->algorithm_ref & 0xFF;
          */
	}
     //exit(1);
     if (drvdata->selected == SELECT_MF ||
			drvdata->selected == SELECT_EFDIR) {
		drvdata->invalid_senv = 1;
          printf("invalid_senv !!!!\n");
		return 0;
	}
     r= iso_ops->set_security_env(card,env,se_num);
     if (r == 0) {
         drvdata->invalid_senv = 0; 
     }
     return r;

}

static int jcop4_compute_signature(sc_card_t *card,
				  const u8 * data, size_t datalen,
				  u8 * out, size_t outlen) {

     int r;
     struct sc_context *ctx = card->ctx;
     struct sc_card_driver *iso_drv = sc_get_iso7816_driver();
     const struct sc_card_operations *iso_ops = iso_drv->ops;

     
     const u8* tmp_sbuf=data;
     size_t tmp_sbuf_datalen=datalen;

     assert(card != NULL && data != NULL && out != NULL);

     
     ctx = card->ctx;
	LOG_FUNC_CALLED(ctx);
                   
     
     if (tmp_sbuf_datalen >= 256) {
          //printf("HHHH\n");
          r=card->ops->decipher(card, data , datalen, out, outlen);
          return r;
     }
		


     
	//printf("CHECK ME exit\n");
	 //exit(1);
     //r=card->ops->compute_signature(card, tmp_sbuf, tmp_sbuf_datalen, out, outlen);
     r = iso_ops->compute_signature(card, tmp_sbuf, tmp_sbuf_datalen, out, outlen);
     //r = iso_ops->decipher(card,tmp_sbuf, tmp_sbuf_datalen, out, outlen);
	 //exit(1);
     return r;
     }

/*
  Card does not use a padding indicator byte, so we cannotdelegate to iso7816_decipher()
*/
static int jcop4_decipher(struct sc_card *card,
			 const u8 * crgram, size_t crgram_len,
			 u8 * out, size_t outlen) {


	sc_apdu_t apdu;
	u8 resp[256];
	int r;

	LOG_FUNC_CALLED(card->ctx);

	sc_format_apdu(card, &apdu, SC_APDU_CASE_4, 0x2A, 0x80, 0x86);
	apdu.data = crgram;
	apdu.datalen = crgram_len;
	apdu.lc = crgram_len;

	apdu.resp = resp;
	apdu.resplen = sizeof(resp);
	apdu.le = sizeof(resp);

	
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_RET(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_RET(card->ctx, r, "PSO DECIPHER failed");

	if (apdu.resplen > outlen)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_BUFFER_TOO_SMALL);
	memcpy(out, resp, apdu.resplen);
	LOG_FUNC_RETURN(card->ctx, (int)apdu.resplen);
}

/*

static int jcop_generate_key(struct sc_card *card, struct sc_cardctl_jcop_genkey *a) {
     int modlen;
     int r;
     struct sc_apdu apdu;
     u8 rbuf[SC_MAX_APDU_BUFFER_SIZE];
     u8 sbuf[SC_MAX_APDU_BUFFER_SIZE];
     u8 *p;
     int is_f4;
     jcop_private_data_t *drvdata=DRVDATA(card);

     if (drvdata->selected == SELECT_MF || drvdata->selected == SELECT_EFDIR )
	  return sc_check_sw(card, 0x6A, 0x82);

     is_f4=0;
     
     if (a->exponent == 0x10001) {
	  is_f4=1;
     } else if (a->exponent != 3) {
	  sc_perror(card->ctx, SC_ERROR_NOT_SUPPORTED, "Invalid exponent");
	  return SC_ERROR_NOT_SUPPORTED;
     }
     
     sc_format_apdu(card, &apdu, SC_APDU_CASE_3_SHORT, 0x22, 0xC1, 0xB6);

     p = sbuf;
     *p++ = 0x80;    // algorithm reference 
     *p++ = 0x01;
     *p++ = is_f4 ? 0x6E : 0x6D;
     
     *p++ = 0x81;
     *p++ = a->pub_file_ref.len;
     memcpy(p, a->pub_file_ref.value, a->pub_file_ref.len);
     p += a->pub_file_ref.len;
     
     *p++ = 0x81;
     *p++ = a->pri_file_ref.len;
     memcpy(p, a->pri_file_ref.value, a->pri_file_ref.len);
     p += a->pri_file_ref.len;
     
     r = p - sbuf;

     apdu.lc = r;
     apdu.datalen = r;
     apdu.data = sbuf;
     apdu.resplen = 0;
     r = sc_transmit_apdu(card, &apdu);
     if (r) {
	  sc_perror(card->ctx, r, "APDU transmit failed");
	  return r;
     }
     r = sc_check_sw(card, apdu.sw1, apdu.sw2);
     if (r) {
	  sc_perror(card->ctx, r, "Card returned error");
	  return r;
     }

     sc_format_apdu(card, &apdu, SC_APDU_CASE_2_SHORT, 0x46, 0, 0);

     apdu.le = 256;
     apdu.resp=rbuf;
     apdu.resplen = sizeof(rbuf);
     
     r = sc_transmit_apdu(card, &apdu);
     if (r) {
	  sc_perror(card->ctx, r, "APDU transmit failed");
	  return r;
     }
     r = sc_check_sw(card, apdu.sw1, apdu.sw2);
     if (r) {
	  sc_perror(card->ctx, r, "Card returned error");
	  return r;
     }

     if (rbuf[0] != 0x4) {
	  return SC_ERROR_INVALID_DATA;
     }
     modlen=rbuf[1] * 32;
     if (a->pubkey_len < rbuf[1])
	  return SC_ERROR_BUFFER_TOO_SMALL;
     a->pubkey_len=rbuf[1] * 4;
     memcpy(a->pubkey, &rbuf[2], a->pubkey_len);
     
     return 0;
}
*/

static int jcop_card_ctl(struct sc_card *card, unsigned long cmd, void *ptr)
{
        switch (cmd) {
        case SC_CARDCTL_GET_DEFAULT_KEY:
                return jcop_get_default_key(card,
                                (struct sc_cardctl_default_key *) ptr);
          /*
        case SC_CARDCTL_JCOP_LOCK:
	     // XXX implement me 
	     return SC_ERROR_NOT_SUPPORTED;
        case SC_CARDCTL_JCOP_GENERATE_KEY:
                return jcop_generate_key(card,
                                (struct sc_cardctl_jcop_genkey *) ptr);
          */
        }

        return SC_ERROR_NOT_SUPPORTED;
}


/* "The PINs are "global" in a PKCS#15 sense, meaning that they remain valid
 *  until card reset! Selecting another applet doesn't invalidate the PINs, 
 *  you need to reset the card." - javacard@zurich.ibm.com, when asked about 
 *  how to invalidate logged in pins.
*/
static int jcop_logout(struct sc_card *card)
{
     return 0; /* Can't */
}


static int
jcop_read_record(struct sc_card *card, unsigned int rec_nr, unsigned int idx,
		u8 *buf, size_t count, unsigned long flags)
{
	struct sc_apdu apdu;
	int r;


	if (rec_nr > 0xFF)
		LOG_FUNC_RETURN(card->ctx, SC_ERROR_INVALID_ARGUMENTS);
	//printf("JCOP rec_nr:%d idx:%d\n",rec_nr,idx);
	//	exit(1);
	if (idx == 0) {
		sc_format_apdu(card, &apdu, SC_APDU_CASE_2, 0xB2, rec_nr, 0);
		apdu.le = count;
		apdu.resplen = count;
		apdu.resp = buf;
	} else {
   	  // B3 ist not supported (SW1 SW2 == 6A 81)  "Function not supported"
          return SC_ERROR_FILE_END_REACHED;
	}
	apdu.p2 = (flags & SC_RECORD_EF_ID_MASK) << 3;
	if (flags & SC_RECORD_BY_REC_NR)
		apdu.p2 |= 0x04;

	iso7816_fixup_transceive_length(card, &apdu);
	r = sc_transmit_apdu(card, &apdu);
	LOG_TEST_GOTO_ERR(card->ctx, r, "APDU transmit failed");
	r = sc_check_sw(card, apdu.sw1, apdu.sw2);
	LOG_TEST_GOTO_ERR(card->ctx, r, "Card returned error");

	if (idx == 0) {
	  r = (int)apdu.resplen;
	} else {
          r=SC_ERROR_INTERNAL;
        }


err:
	LOG_FUNC_RETURN(card->ctx, r);
}




static struct sc_card_driver * sc_get_driver(void)
{
     struct sc_card_driver *iso_drv = sc_get_iso7816_driver();

     if (iso_ops == NULL)
		iso_ops = iso_drv->ops;

     jcop_ops = *iso_drv->ops;
     jcop_ops.match_card = jcop_match_card;
     jcop_ops.init = jcop_init;
     jcop_ops.finish = jcop_finish;
     jcop_ops.read_record = jcop_read_record;
     //jcop_ops.read_binary = jcop_read_binary;
     jcop_ops.write_binary = jcop_write_binary;
     jcop_ops.update_binary = jcop_update_binary;
     jcop_ops.select_file = jcop4_select_file;
     jcop_ops.create_file = jcop_create_file;
     jcop_ops.delete_file = jcop_delete_file;
     //jcop_ops.list_files = jcop_list_files;
     jcop_ops.set_security_env = jcop4_set_security_env;
     jcop_ops.compute_signature = jcop4_compute_signature;
     jcop_ops.decipher = jcop4_decipher;
     jcop_ops.logout = jcop_logout;
     jcop_ops.process_fci = jcop_process_fci;
     jcop_ops.card_ctl = jcop_card_ctl;
     
     return &jcop_drv;
}

#if 1
struct sc_card_driver * sc_get_jcop_driver(void)
{
     return sc_get_driver();
}
#endif


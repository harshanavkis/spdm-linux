// SPDX-License-Identifier: GPL-2.0+
/*
 * ECDSA X9.62 signature encoding
 *
 * Copyright (c) 2021 IBM Corporation
 * Copyright (c) 2024 Intel Corporation
 */

#include <linux/asn1_decoder.h>
#include <linux/err.h>
#include <linux/module.h>
#include <crypto/akcipher.h>
#include <crypto/algapi.h>
#include <crypto/internal/akcipher.h>
#include <crypto/internal/ecc.h>

#include "ecdsasignature.asn1.h"

struct ecdsa_x962_ctx {
	struct crypto_akcipher *child;
};

struct ecdsa_x962_request {
	u64 r[ECC_MAX_DIGITS];
	u64 s[ECC_MAX_DIGITS];
	struct akcipher_request child_req;
};

/* Get the r and s components of a signature from the X.509 certificate. */
static int ecdsa_get_signature_rs(u64 *dest, size_t hdrlen, unsigned char tag,
				  const void *value, size_t vlen,
				  unsigned int ndigits)
{
	size_t bufsize = ndigits * sizeof(u64);
	const char *d = value;

	if (!value || !vlen || vlen > bufsize + 1)
		return -EINVAL;

	if (vlen > bufsize) {
		/* skip over leading zeros that make 'value' a positive int */
		if (*d == 0) {
			vlen -= 1;
			d++;
		} else {
			return -EINVAL;
		}
	}

	ecc_digits_from_bytes(d, vlen, dest, ndigits);

	return 0;
}

static unsigned int ecdsa_get_ndigits(struct akcipher_request *req)
{
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	struct ecdsa_x962_ctx *ctx = akcipher_tfm_ctx(tfm);

	return DIV_ROUND_UP(crypto_akcipher_maxsize(ctx->child), sizeof(u64));
}

int ecdsa_get_signature_r(void *context, size_t hdrlen, unsigned char tag,
			  const void *value, size_t vlen)
{
	struct akcipher_request *req = context;
	struct ecdsa_x962_request *req_ctx = akcipher_request_ctx(req);

	return ecdsa_get_signature_rs(req_ctx->r, hdrlen, tag, value, vlen,
				      ecdsa_get_ndigits(req));
}

int ecdsa_get_signature_s(void *context, size_t hdrlen, unsigned char tag,
			  const void *value, size_t vlen)
{
	struct akcipher_request *req = context;
	struct ecdsa_x962_request *req_ctx = akcipher_request_ctx(req);

	return ecdsa_get_signature_rs(req_ctx->s, hdrlen, tag, value, vlen,
				      ecdsa_get_ndigits(req));
}

static int ecdsa_x962_verify(struct akcipher_request *req)
{
	struct ecdsa_x962_request *req_ctx = akcipher_request_ctx(req);
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	struct ecdsa_x962_ctx *ctx = akcipher_tfm_ctx(tfm);
	int err;

	err = asn1_ber_decoder(&ecdsasignature_decoder, req,
			       req->sig, req->sig_len);
	if (err < 0)
		return err;

	akcipher_request_set_tfm(&req_ctx->child_req, ctx->child);
	akcipher_request_set_crypt(&req_ctx->child_req, req_ctx, req->digest,
				   ECC_MAX_BYTES * 2, req->digest_len);

	return crypto_akcipher_verify(&req_ctx->child_req);
}

static unsigned int ecdsa_x962_max_size(struct crypto_akcipher *tfm)
{
	struct ecdsa_x962_ctx *ctx = akcipher_tfm_ctx(tfm);

	return crypto_akcipher_maxsize(ctx->child);
}

static int ecdsa_x962_set_pub_key(struct crypto_akcipher *tfm, const void *key,
				  unsigned int keylen)
{
	struct ecdsa_x962_ctx *ctx = akcipher_tfm_ctx(tfm);

	return crypto_akcipher_set_pub_key(ctx->child, key, keylen);
}

static int ecdsa_x962_init_tfm(struct crypto_akcipher *tfm)
{
	struct akcipher_instance *inst = akcipher_alg_instance(tfm);
	struct crypto_akcipher_spawn *spawn = akcipher_instance_ctx(inst);
	struct ecdsa_x962_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct crypto_akcipher *child_tfm;

	child_tfm = crypto_spawn_akcipher(spawn);
	if (IS_ERR(child_tfm))
		return PTR_ERR(child_tfm);

	ctx->child = child_tfm;

	akcipher_set_reqsize(tfm, sizeof(struct ecdsa_x962_request) +
				  crypto_akcipher_reqsize(child_tfm));

	return 0;
}

static void ecdsa_x962_exit_tfm(struct crypto_akcipher *tfm)
{
	struct ecdsa_x962_ctx *ctx = akcipher_tfm_ctx(tfm);

	crypto_free_akcipher(ctx->child);
}

static void ecdsa_x962_free(struct akcipher_instance *inst)
{
	struct crypto_akcipher_spawn *spawn = akcipher_instance_ctx(inst);

	crypto_drop_akcipher(spawn);
	kfree(inst);
}

static int ecdsa_x962_create(struct crypto_template *tmpl, struct rtattr **tb)
{
	struct crypto_akcipher_spawn *spawn;
	struct akcipher_instance *inst;
	struct akcipher_alg *ecdsa_alg;
	u32 mask;
	int err;

	err = crypto_check_attr_type(tb, CRYPTO_ALG_TYPE_AKCIPHER, &mask);
	if (err)
		return err;

	inst = kzalloc(sizeof(*inst) + sizeof(*spawn), GFP_KERNEL);
	if (!inst)
		return -ENOMEM;

	spawn = akcipher_instance_ctx(inst);

	err = crypto_grab_akcipher(spawn, akcipher_crypto_instance(inst),
				   crypto_attr_alg_name(tb[1]), 0, mask);
	if (err)
		goto err_free_inst;

	ecdsa_alg = crypto_spawn_akcipher_alg(spawn);

	err = -EINVAL;
	if (strncmp(ecdsa_alg->base.cra_name, "ecdsa", 5) != 0)
		goto err_free_inst;

	err = crypto_inst_setname(akcipher_crypto_instance(inst), tmpl->name,
				  &ecdsa_alg->base);
	if (err)
		goto err_free_inst;

	inst->alg.base.cra_priority = ecdsa_alg->base.cra_priority;
	inst->alg.base.cra_ctxsize = sizeof(struct ecdsa_x962_ctx);

	inst->alg.init = ecdsa_x962_init_tfm;
	inst->alg.exit = ecdsa_x962_exit_tfm;

	inst->alg.verify = ecdsa_x962_verify;
	inst->alg.max_size = ecdsa_x962_max_size;
	inst->alg.set_pub_key = ecdsa_x962_set_pub_key;

	inst->free = ecdsa_x962_free;

	err = akcipher_register_instance(tmpl, inst);
	if (err) {
err_free_inst:
		ecdsa_x962_free(inst);
	}
	return err;
}

struct crypto_template ecdsa_x962_tmpl = {
	.name = "x962",
	.create = ecdsa_x962_create,
	.module = THIS_MODULE,
};

MODULE_ALIAS_CRYPTO("x962");

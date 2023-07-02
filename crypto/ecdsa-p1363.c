// SPDX-License-Identifier: GPL-2.0
/*
 * ECDSA P1363 signature encoding
 *
 * Copyright (c) 2024 Intel Corporation
 */

#include <linux/err.h>
#include <linux/module.h>
#include <crypto/akcipher.h>
#include <crypto/algapi.h>
#include <crypto/internal/akcipher.h>
#include <crypto/internal/ecc.h>

struct ecdsa_p1363_ctx {
	struct crypto_akcipher *child;
};

struct ecdsa_p1363_request {
	u64 r[ECC_MAX_DIGITS];
	u64 s[ECC_MAX_DIGITS];
	struct akcipher_request child_req;
};

static int ecdsa_p1363_verify(struct akcipher_request *req)
{
	struct ecdsa_p1363_request *req_ctx = akcipher_request_ctx(req);
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	struct ecdsa_p1363_ctx *ctx = akcipher_tfm_ctx(tfm);
	unsigned int keylen = crypto_akcipher_maxsize(ctx->child);
	unsigned int ndigits = DIV_ROUND_UP(keylen, sizeof(u64));

	if (req->sig_len != keylen * 2)
		return -EINVAL;

	ecc_digits_from_bytes(req->sig, keylen, req_ctx->r, ndigits);
	ecc_digits_from_bytes(req->sig + keylen, keylen, req_ctx->s, ndigits);

	akcipher_request_set_tfm(&req_ctx->child_req, ctx->child);
	akcipher_request_set_crypt(&req_ctx->child_req, req_ctx, req->digest,
				   ECC_MAX_BYTES * 2, req->digest_len);

	return crypto_akcipher_verify(&req_ctx->child_req);
}

static unsigned int ecdsa_p1363_max_size(struct crypto_akcipher *tfm)
{
	struct ecdsa_p1363_ctx *ctx = akcipher_tfm_ctx(tfm);

	return crypto_akcipher_maxsize(ctx->child);
}

static int ecdsa_p1363_set_pub_key(struct crypto_akcipher *tfm, const void *key,
				   unsigned int keylen)
{
	struct ecdsa_p1363_ctx *ctx = akcipher_tfm_ctx(tfm);

	return crypto_akcipher_set_pub_key(ctx->child, key, keylen);
}

static int ecdsa_p1363_init_tfm(struct crypto_akcipher *tfm)
{
	struct akcipher_instance *inst = akcipher_alg_instance(tfm);
	struct crypto_akcipher_spawn *spawn = akcipher_instance_ctx(inst);
	struct ecdsa_p1363_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct crypto_akcipher *child_tfm;

	child_tfm = crypto_spawn_akcipher(spawn);
	if (IS_ERR(child_tfm))
		return PTR_ERR(child_tfm);

	ctx->child = child_tfm;

	akcipher_set_reqsize(tfm, sizeof(struct ecdsa_p1363_request) +
				  crypto_akcipher_reqsize(child_tfm));

	return 0;
}

static void ecdsa_p1363_exit_tfm(struct crypto_akcipher *tfm)
{
	struct ecdsa_p1363_ctx *ctx = akcipher_tfm_ctx(tfm);

	crypto_free_akcipher(ctx->child);
}

static void ecdsa_p1363_free(struct akcipher_instance *inst)
{
	struct crypto_akcipher_spawn *spawn = akcipher_instance_ctx(inst);

	crypto_drop_akcipher(spawn);
	kfree(inst);
}

static int ecdsa_p1363_create(struct crypto_template *tmpl, struct rtattr **tb)
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
	inst->alg.base.cra_ctxsize = sizeof(struct ecdsa_p1363_ctx);

	inst->alg.init = ecdsa_p1363_init_tfm;
	inst->alg.exit = ecdsa_p1363_exit_tfm;

	inst->alg.verify = ecdsa_p1363_verify;
	inst->alg.max_size = ecdsa_p1363_max_size;
	inst->alg.set_pub_key = ecdsa_p1363_set_pub_key;

	inst->free = ecdsa_p1363_free;

	err = akcipher_register_instance(tmpl, inst);
	if (err) {
err_free_inst:
		ecdsa_p1363_free(inst);
	}
	return err;
}

struct crypto_template ecdsa_p1363_tmpl = {
	.name = "p1363",
	.create = ecdsa_p1363_create,
	.module = THIS_MODULE,
};

MODULE_ALIAS_CRYPTO("p1363");

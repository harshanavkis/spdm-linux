#include <crypto/aead.h>
#include <linux/scatterlist.h>

#include <misc/qemu_ivshmem.h>

#include "internal.h"

static struct disagg_mmio_data ctx;

static struct mmio_message *msg;

#ifdef CONFIG_DISAGG_DEBUG_MMIO_SEC
static void my_print_hexdump(const char *prefix, const void *buf, size_t len) {
	print_hex_dump(KERN_INFO, prefix, DUMP_PREFIX_NONE, 32, 1, buf, len, false);
}
#endif

/*
 * Encrypts @data of @count and prepends authentication tag.
 * @return buffer with result (size of return buffer == count + authsize)
 */
static void *encrypt(const u8 *data, size_t count)
{
#ifdef CONFIG_DISAGG_DEBUG_MMIO_SEC
	pr_info("disagg_mmio_encrypt:\n");
	pr_info("counter: %llu", *ctx.crypto.counter);
	my_print_hexdump("Plaintext: ", data, count);
#endif

	sg_set_buf(&ctx.sg[0], data, count);
	sg_set_buf(&ctx.sg_enc[0], ctx.buf_enc + ctx.crypto.authsize, count);
	aead_request_set_crypt(ctx.crypto.req, ctx.sg, ctx.sg_enc, count, ctx.crypto.iv);
	if (crypto_wait_req(crypto_aead_encrypt(ctx.crypto.req), &ctx.crypto.wait)) {
		pr_err("disagg_mmio_encrypt: encryption failed\n");
		return NULL;
	}

	++(*ctx.crypto.counter);

#ifdef CONFIG_DISAGG_DEBUG_MMIO_SEC
	pr_info("cipher-size (only encrypted data): %ld\n", count);
	my_print_hexdump("ciphertext: ", ctx.buf_enc + ctx.crypto.authsize, count);
	my_print_hexdump("Auth tag: ", ctx.buf_enc, ctx.crypto.authsize);
	pr_info("\n");
#endif

	return ctx.buf_enc;
}

/*
 * Expects the encrypted data in @crypto->buf_dec. sizeof(data in crypto->buf_dec) == count + authsize
 * Writes the decrypted data into @buf.
 * Returns 1 for error, 0 for success
 */
static int decrypt(u8 *buf, size_t count)
{
	int err;

#ifdef CONFIG_DISAGG_DEBUG_MMIO_SEC
	pr_info("disagg_mmio_decrypt:\n");
	pr_info("counter: %llu", *ctx.crypto.counter);
	pr_info("cipher-size (only encrypted data): %ld\n", count);
	my_print_hexdump("ciphertext: ", ctx.buf_dec, count);
	my_print_hexdump("Auth Tag: ", ctx.buf_dec + count, ctx.crypto.authsize);
#endif

	sg_set_buf(&ctx.sg[0], buf, count);
	aead_request_set_crypt(ctx.crypto.req, ctx.sg_dec, ctx.sg, count + ctx.crypto.authsize, ctx.crypto.iv);
	err = crypto_wait_req(crypto_aead_decrypt(ctx.crypto.req), &ctx.crypto.wait);
	if (err) {
		if (err == -EBADMSG) {
			pr_err("disagg_mmio_decrypt: Authetication failed\n");
			return 1;
		}
		pr_err("disagg_mmio_decrypt: decryption failed\n");
		return 1;
	}

#ifdef CONFIG_DISAGG_DEBUG_MMIO_SEC
	my_print_hexdump("Plaintext: ", buf, count);
	pr_info("\n");
#endif

	++(*ctx.crypto.counter);
	return 0;
}

int mmio_read(u64 size, u64 addr, unsigned long *val)
{
	void *buf;
	u64 offset = disagg_ioremap_virt_to_offset(addr);

#ifdef CONFIG_DISAGG_DEBUG_MMIO
	pr_info("mmio_read: Address: %llx\n", addr);
#endif

	msg->address = offset;
	msg->operation = DISAGG_DEV_OP_READ;
	msg->length = size;

	buf = encrypt((void *)msg, sizeof(*msg) - sizeof(msg->value));
	if (!buf)
		return 1;

	ivshmem_mmio_write(buf, sizeof(*msg) - sizeof(msg->value) + ctx.crypto.authsize);

	//ivshmem_mmio_read(ctx.buf_dec, sizeof(msg->value) + ctx.crypto.authsize);
	ivshmem_mmio_read(ctx.buf_dec, size + ctx.crypto.authsize);

	if (decrypt((void *)val, size) != 0)
		return 1;

	return 0;
}

int mmio_write(u64 size, u64 addr, unsigned long val)
{
	void *buf;
	u64 offset = disagg_ioremap_virt_to_offset(addr);

#ifdef CONFIG_DISAGG_DEBUG_MMIO
	pr_info("mmio_write: Address: %llx\n", addr);
#endif

	msg->address = offset;
	msg->operation = DISAGG_DEV_OP_WRITE;
	msg->length = size;
	msg->value = val;

	buf = encrypt((void *)msg, sizeof(*msg) - sizeof(msg->value));
	if (!buf)
		return 1;

	ivshmem_mmio_write(buf, sizeof(*msg) - sizeof(msg->value) + ctx.crypto.authsize);


	buf = encrypt((void *)val, size);

	ivshmem_mmio_write(buf, size + ctx.crypto.authsize);


	return 0;
}


int disagg_init_mmio(u8 *key, int keylen)
{
	struct disagg_crypto *crypto = &ctx.crypto;
	struct crypto_aead *tfm = NULL;
	struct aead_request *req = NULL;
	u8 *iv;
	int iv_size;
	crypto->authsize = 16; // size of the authentication code
	int adlen = 0; // No ad in our case

	// Create transformation object
	tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(tfm)) {
		pr_err("disagg_init_crypto_mmio: AES/GCM alloc_aead failed\n");
		return 1;
	} else {
		pr_info("disagg_init_crypto_mmio: gcm(aes): name: %s, driver_name: %s\n",
					tfm->base.__crt_alg->cra_name, 
					tfm->base.__crt_alg->cra_driver_name);
	}

	/*** Init IV ***/
	iv_size = crypto_aead_ivsize(tfm);
	pr_info("iv_size: %d", iv_size);
	if (iv_size < sizeof(crypto->counter)) {
		pr_info("Error: iv_size too small for this implementation");
		goto error_free_aead;
	}
	iv = kmalloc(iv_size, GFP_KERNEL);
	if (iv == NULL) {
		pr_err("disagg_init_crypto_mmio: kmalloc of IV-space failed\n");
		goto error_free_aead;
	}
	memset((void *) iv, 0x0, iv_size);
	// IV will alias the counter, allows freshness
	crypto->counter = (u64 *) iv;
	*crypto->counter = 0;

	// Set key 
	if (crypto_aead_setkey(tfm, key, keylen) < 0) {
		pr_err("disagg_init_crypto_mmio: setkey failed\n");
		goto error_free_aead;
	}

	// Set size of authentication code
	if (crypto_aead_setauthsize(tfm, crypto->authsize) < 0) {
		pr_err("disagg_init_crypto_mmio: setauthsize failed\n");
		goto error_free_aead;
	}

	// alloc buffers used in enc/dec
	ctx.size_buffers = crypto->authsize + 64;
	ctx.buf_enc = kmalloc(ctx.size_buffers, GFP_KERNEL); // extra 64 bytes for guest_message_header should be enough
	if (!ctx.buf_enc) {
		pr_err("disagg_init_crypto_mmio: kmalloc failed\n");
		goto error_free_aead;
	}
	ctx.buf_dec = kmalloc(ctx.size_buffers, GFP_KERNEL); // extra 64 bytes for guest_message_header should be enough
	if (!ctx.buf_dec) {
		pr_err("disagg_init_crypto_mmio: kmalloc failed\n");
		goto error_free_buf;
	}

	crypto_aead_clear_flags(tfm, ~0);

	// Obtain the request structures
	req = aead_request_alloc(tfm, GFP_KERNEL);
	if (req == NULL) {
		pr_err("disagg_init_crypto_mmio: request_alloc failed\n");
		goto error_free_buf2;
	}

	// Init wait object
	crypto_init_wait(&crypto->wait);

	// Set callback function which will never be called, because we wait synchronously
	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, &crypto->wait);

	// Set size of associated data
	// no AD in our case
	aead_request_set_ad(req, adlen);

	crypto->tfm = tfm;
	crypto->req = req;
	crypto->iv = iv;
	sg_set_buf(&ctx.sg_enc[1], ctx.buf_enc, crypto->authsize);
	sg_set_buf(&ctx.sg_dec[0], ctx.buf_dec, ctx.size_buffers);

	// Alloc message structure object
	msg = kmalloc(sizeof(*msg), GFP_KERNEL);
	if (!msg)
		return -ENOMEM;
	return 0;

error_free_buf2:
	kfree(ctx.buf_dec);
error_free_buf:
	kfree(ctx.buf_enc);
error_free_aead:
	crypto_free_aead(tfm);
	kfree(iv);
	return 1;
}

void disagg_exit_mmio(void)
{
	aead_request_free(ctx.crypto.req);
	crypto_free_aead(ctx.crypto.tfm);
	kfree(ctx.crypto.iv);
	kfree(msg);
}


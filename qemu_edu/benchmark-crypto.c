/* many things copied from  https://cirosantilli.com/linux-kernel-module-cheat#qemu-edu */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/timekeeping.h> // for time measurement
#include <crypto/aead.h>
#include <linux/scatterlist.h>

static long write_size = 1;
module_param(write_size, long, 0);
MODULE_PARM_DESC(write_size, "The byte size of the MMIO access. Must be one of {1, 2, 4, 8}");

static long count_ops = 1;
module_param(count_ops, long, 0);
MODULE_PARM_DESC(count_ops, "Number of MMIO operations");

static long crypto = 0;
module_param(crypto, long, 0);
MODULE_PARM_DESC(crypto, "Number of MMIO operations");

/* Module handling */
static int __init my_init(void)
{
pr_info("here 0\n");
	struct crypto_aead *tfm = NULL;
	struct aead_request *req = NULL;
	u8 *iv = NULL;
	int iv_size;
	u8 *key = kmalloc(64, GFP_KERNEL);
	u64 *counter = NULL;
	u64 authsize = 16; // size of the authentication code
	int adlen = 0; // No ad in our case
	struct crypto_wait wait; // Used to make calls to crypto API synchronous

pr_info("here 1\n");
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

pr_info("here 2\n");
	/*** Init IV ***/
	iv_size = crypto_aead_ivsize(tfm);
	pr_info("iv_size: %d", iv_size);
	if (iv_size < sizeof(counter)) {
		pr_info("Error: iv_size too small for this implementation");
		goto err;
	}
	iv = kmalloc(iv_size, GFP_KERNEL);
	if (iv == NULL) {
		pr_err("disagg_init_crypto_mmio: kmalloc of IV-space failed\n");
		goto err;
	}
	memset((void *) iv, 0x0, iv_size);
	// IV will alias the counter, allows freshness
	counter = (u64 *) iv;
	*counter = 0;

pr_info("here 3\n");
	// Set key 
	if (crypto_aead_setkey(tfm, key, 32) < 0) {
		pr_err("disagg_init_crypto_mmio: setkey failed\n");
		goto err;
	}

	// Set size of authentication code
	if (crypto_aead_setauthsize(tfm, authsize) < 0) {
		pr_err("disagg_init_crypto_mmio: setauthsize failed\n");
		goto err;
	}

	crypto_aead_clear_flags(tfm, ~0);
pr_info("here 4\n");

	// Obtain the request structures
	req = aead_request_alloc(tfm, GFP_KERNEL);
	if (req == NULL) {
		pr_err("disagg_init_crypto_mmio: request_alloc failed\n");
		goto err;
	}

	// Init wait object
	crypto_init_wait(&wait);

	// Set callback function which will never be called, because we wait synchronously
	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, &wait);

	// Set size of associated data
	// no AD in our case
	aead_request_set_ad(req, adlen);


	/*******************************************************************/
	/*******************************************************************/

	pr_info("here 5\n");

	/***************** Benchmarks *******************/
	if (crypto) {
		ktime_t start, end;

		char *buf = kmalloc(9000, GFP_KERNEL);
		char *buf2 = kmalloc(9000, GFP_KERNEL);
		memset(buf, 0xab, 9000);


		struct scatterlist sg_src[2] = {};
		struct scatterlist sg_dst[2] = {};

		struct scatterlist sg_src2[2] = {};
		struct scatterlist sg_dst2[2] = {};


		for (long i = 0; i < count_ops; ++i) {
			/********* Encryption **********/
			sg_mark_end(&sg_src[0]);
			sg_mark_end(&sg_dst[1]);

			sg_set_buf(&sg_src[0], buf, write_size);
			sg_set_buf(&sg_dst[0], buf2 + authsize, write_size);
			sg_set_buf(&sg_dst[1], buf2, authsize);

			start = ktime_get();
			aead_request_set_crypt(req, sg_src, sg_dst, write_size, iv);
			if (crypto_wait_req(crypto_aead_encrypt(req), &wait)) {
				pr_err("encryption failed\n");
				return 1;
			}
			end = ktime_get();

			if (crypto == 1)
				pr_info("time measured: %lu;%llu end\n", write_size, (u64) ktime_to_ns(end) - (u64) ktime_to_ns(start));

			/*********** Decryption ************/
			sg_mark_end(&sg_src2[1]);
			sg_mark_end(&sg_dst2[0]);

			sg_set_buf(&sg_src2[0], buf2 + authsize, write_size);
			sg_set_buf(&sg_src2[1], buf2, authsize);
			sg_set_buf(&sg_dst2[0], buf, write_size);

			start = ktime_get();
			aead_request_set_crypt(req, sg_src2, sg_dst2, write_size + authsize, iv);
			if (crypto_wait_req(crypto_aead_decrypt(req), &wait)) {
				pr_err("decryption failed\n");
				return 1;
			}
			end = ktime_get();
			if (crypto == 2)
				pr_info("time measured: %lu;%llu end\n", write_size, (u64) ktime_to_ns(end) - (u64) ktime_to_ns(start));

			++(*counter);
		}

		kfree(buf);
		kfree(buf2);
	}

	aead_request_free(req);
	crypto_free_aead(tfm);
	kfree(key);
	kfree(iv);


	return 0;

err:
	return 1;
}

static void __exit my_exit(void)
{
	pr_info("my_exit\n");
};

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Driver for the qemu EDU device");
module_init(my_init);
module_exit(my_exit);

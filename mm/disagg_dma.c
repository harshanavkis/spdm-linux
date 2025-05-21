#include <linux/mm.h>
#include <misc/qemu_ivshmem.h>
#include <crypto/aead.h>
#include <linux/scatterlist.h>

//#define CONFIG_DISAGG_DEBUG_DMA_SEC

disagg_dma_allocator_t disagg_dma_allocator;

int disagg_dma_allocator_init(u8 *key, int keylen)
{
	pr_info("disagg_dma_allocator_init");
        disagg_dma_allocator.shmem_dma = NULL;
	disagg_dma_allocator.dma_size = 0;
	disagg_dma_allocator.free = 0;
	spin_lock_init(&disagg_dma_allocator.lock);

	struct crypto_aead *tfm = NULL;
	struct aead_request *req = NULL;
	u8 *iv = NULL;
	int iv_size;
	disagg_dma_allocator.crypto.authsize = 16; // size of the authentication code
	int adlen = 0; // No ad in our case

	// Create transformation object
	tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(tfm)) {
	    pr_err("disagg_dma_allocator_init: AES/GCM alloc_aead failed\n");
	    return 1;
	}

	// Init IV
	iv_size = crypto_aead_ivsize(tfm);
	pr_info("iv_size: %d", iv_size);
	if (iv_size < sizeof(disagg_dma_allocator.crypto.counter)) {
	    pr_info("Error: iv_size too small for this implementation");
	    goto error_free_aead;
	}
	iv = kmalloc(iv_size, GFP_KERNEL);
	if (iv == NULL) {
	    pr_err("disagg_init_crypto: kmalloc of IV-space failed\n");
	    goto error_free_aead;
	}
	memset((void *) iv, 0x0, iv_size);
	// IV will alias the counter, allows freshness
	disagg_dma_allocator.crypto.counter = (u64 *) iv;
	*disagg_dma_allocator.crypto.counter = 0;

	// Init and set key 
	memset((void *) key, 0x00, keylen);
	if (crypto_aead_setkey(tfm, key, keylen) < 0) {
	    pr_err("disagg_init_crypto: setkey failed\n");
	    goto error_free_aead;
	}

	// Set size of authentication code
	if (crypto_aead_setauthsize(tfm, disagg_dma_allocator.crypto.authsize) < 0) {
	    pr_err("disagg_init_crypto: setauthsize failed\n");
	    goto error_free_aead;
	}

	crypto_aead_clear_flags(tfm, ~0);

	// Obtain the request structures
	req = aead_request_alloc(tfm, GFP_KERNEL);
	if (req == NULL) {
	    pr_err("disagg_init_crypto: request_alloc failed\n");
	    goto error_free_aead;
	}

	// Init wait object
	crypto_init_wait(&disagg_dma_allocator.crypto.wait);

	// Set callback function which will never be called, because we wait synchronously
	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, &disagg_dma_allocator.crypto.wait);

	// Set size of associated data
	// no AD in our case
	aead_request_set_ad(req, adlen);

	disagg_dma_allocator.crypto.tfm = tfm;
	disagg_dma_allocator.crypto.req = req;
	disagg_dma_allocator.crypto.iv = iv;

	kfree(key);
	return 0;
error_free_aead:
	crypto_free_aead(tfm);
	kfree(iv);
	kfree(key);
	return 1;
}

static int disagg_dma_encrypt(struct page *page_from, size_t offset, void *to, size_t size)
{
    struct scatterlist sg1[3];
    struct scatterlist sg2[3];

#ifdef CONFIG_DISAGG_DEBUG_DMA_SEC
    pr_info("disagg_dma_encrypt:\n");
    pr_info("counter: %llu", *disagg_dma_allocator.crypto.counter);
#endif

    sg_mark_end(sg1);
    sg_set_page(&sg1[0], page_from, size, offset);
    sg_set_buf(&sg2[0], to, size + disagg_dma_allocator.crypto.authsize);
    aead_request_set_crypt(disagg_dma_allocator.crypto.req, sg1, sg2, size, disagg_dma_allocator.crypto.iv);
    if (crypto_wait_req(crypto_aead_encrypt(disagg_dma_allocator.crypto.req), &disagg_dma_allocator.crypto.wait)) {
	pr_err("disagg_dma_encrypt: encryption failed\n");
	return 1;
    }
     
    ++(*disagg_dma_allocator.crypto.counter);

#ifdef CONFIG_DISAGG_DEBUG_DMA_SEC
    pr_info("cipher-size (only encrypted data): %ld\n", count);
    my_print_hexdump("ciphertext: ", crypto->buf_enc, count);
    my_print_hexdump("Auth tag: ", crypto->buf_enc + count, crypto->authsize);
    pr_info("\n");
#endif

    return 0;
}

/* Allocates a dmu buffer from the shmem region */
dma_addr_t disagg_dma_map_page_attrs(struct device *dev, struct page *page, size_t offset, size_t size, enum dma_data_direction dir, unsigned long attrs) 
{
    dma_addr_t proxy_dma_addr;;
    struct guest_message_header hdr;
    u64 proxy_shmem;

    pr_info("disagg_dma_map_page_attrs\n");

    if (disagg_dma_allocator.shmem_dma == NULL) {
	    pr_err("disagg_dma_map_page_attrs: shared memory not yet ready\n");
	    goto error;
    }

    spin_lock(&disagg_dma_allocator.lock);

    // just a simple one page allocator
    if (size > disagg_dma_allocator.dma_size || disagg_dma_allocator.free == 0) {
	pr_err("disagg_dma_alloc: request not fullfillable");
	goto error;
    }

    disagg_dma_allocator.free = 0;

    // Encrypt the data to shmem
    disagg_dma_encrypt(page, offset, disagg_dma_allocator.shmem_dma, size);

    // read the dma address for the proxy into the handle (for now we assume sizeof(dma_addr_t) == 8)
    if (ivshmem_read_dma_proxy_address(&proxy_shmem, 8) < 8) {
	pr_err("disagg_dma_alloc: reading the proxy addr from shmem failed\n");
	goto error;
    }

    // Provide proxy with information where the encrypted data is placed into shmem
    hdr.address = proxy_shmem;
    hdr.operation = DISAGG_DEV_OP_DMA_MAP;
    hdr.length = size;
    ivshmem_write(&hdr, sizeof(hdr), 0);

    // Read the base address for the proxies dma region
    // Which also servers as a confirmation of completion of decryption
    ivshmem_read(&proxy_dma_addr, 8, 0);

    spin_unlock(&disagg_dma_allocator.lock);

    pr_info("disagg_dma_map_page: dma_handle: 0x%llx\n", (uint64_t) proxy_dma_addr);

    return proxy_dma_addr;

error:
    spin_unlock(&disagg_dma_allocator.lock);
    pr_info("disagg_dma_map_page failed\n");
    return 0;
}

void disagg_dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size, enum dma_data_direction dir, unsigned long attrs)
{
#if 0
    spin_lock(&disagg_dma_allocator.lock);

    if (disagg_dma_allocator.free == 1) {
	pr_err("disagg_dma_free: cannot free already freed buffer\n");
	goto error;
    }

    disagg_dma_allocator.free = 1;

error:
    spin_unlock(&disagg_dma_allocator.lock);
#endif
}


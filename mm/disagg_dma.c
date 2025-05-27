#include <linux/mm.h>
#include <misc/qemu_ivshmem.h>
#include <crypto/aead.h>
#include <linux/scatterlist.h>
#include <linux/pci.h> // for dev_is_pci

#define CONFIG_DISAGG_DEBUG_DMA_SEC

disagg_dma_allocator_t disagg_dma_allocator;

#ifdef CONFIG_DISAGG_DEBUG_DMA_SEC
static void my_print_hexdump(const char *prefix, const void *buf, size_t len) {
    print_hex_dump(KERN_INFO, prefix, DUMP_PREFIX_NONE, 32, 1, buf, len, false);
}
#endif

static void *proxyDMA_to_vmShmem(u64 proxyDMA) {
    if (disagg_dma_allocator.proxyDMA_start > (u64) disagg_dma_allocator.vmShmem_start)
	return (void *) proxyDMA - ((void *)disagg_dma_allocator.proxyDMA_start - disagg_dma_allocator.vmShmem_start);
    else
	return (void *) proxyDMA + (disagg_dma_allocator.vmShmem_start - (void *) disagg_dma_allocator.proxyDMA_start);
}

/*
 * Looks for entry containing the specified range (addr, size)
 * @return NULL for no corresponding entry, the entry otherwise
 */
static struct disagg_dma_entry *disagg_find_entry(dma_addr_t proxyDMA, size_t size)
{
    // right now this is one simple comparision as we only support one buffer
    struct disagg_dma_entry *crt;

    crt = &disagg_dma_allocator.entry;

    if (proxyDMA >= crt->proxyDMA && proxyDMA + size <= crt->proxyDMA + size)
	return crt;

    return NULL;
}

bool disagg_is_dev(struct device *dev) 
{
    struct pci_dev *pdev;

    if (dev_is_pci(dev)) {
	pdev = container_of(dev, struct pci_dev, dev);
    } else {
	return false;
    }

    if (unlikely((pdev->vendor == 0x1234) && (pdev->device == 0x11e8))) {
	return true;
    } else {
	return false;
    }
}

// Requests proxies dma address and writes it into field of disagg_dma_allocator
// Those addresse can then be used to convert from proxyDMA to vmShmem
static int obtain_proxy_address(void) {
    struct guest_message_header hdr;
    u8 *resp = kmalloc(sizeof(void *) * 2, GFP_KERNEL);
    if (resp == NULL) {
	pr_err("kmalloc_failed");
	return 1;
    }

    hdr.address = 0;
    hdr.operation = DISAGG_DEV_OP_ADDR_INIT;
    hdr.length = 8;
    ivshmem_write(&hdr, sizeof(hdr), 0);

    ivshmem_read(resp, 8, 0);

    disagg_dma_allocator.proxyDMA_start = *((u64 *) resp);

    return 0;
}

int disagg_dma_allocator_init(u8 *key, int keylen, void *vmShmem_start, size_t dma_area_size)
{
	pr_info("disagg_dma_allocator_init");
        disagg_dma_allocator.vmShmem_start = vmShmem_start;
	disagg_dma_allocator.dma_area_size = dma_area_size;
	disagg_dma_allocator.free = 1;
	spin_lock_init(&disagg_dma_allocator.lock);

	disagg_dma_allocator.crypto.authsize = 16; // size of the authentication code
	struct crypto_aead *tfm = NULL;
	struct aead_request *req = NULL;
	u8 *iv = NULL;
	int iv_size = 0;
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

	if (obtain_proxy_address() != 0) {
	    pr_err("get_proxy_addresses failed\n");
	    goto error_free_aead;
	}

	return 0;
error_free_aead:
	crypto_free_aead(tfm);
	kfree(iv);
	return 1;
}

static int disagg_dma_encrypt(void *from, void *to, size_t size)
{
    struct scatterlist sg_src[1];
    struct scatterlist sg_dst[1];

#ifdef CONFIG_DISAGG_DEBUG_DMA_SEC
    pr_info("disagg_dma_encrypt:\n");
    pr_info("counter: %llu", *disagg_dma_allocator.crypto.counter);
    my_print_hexdump("Plaintext: ", from, size);
#endif

    sg_mark_end(sg_src);
    sg_mark_end(sg_dst);
    sg_set_buf(&sg_src[0], from, size);
    sg_set_buf(&sg_dst[0], to, size + disagg_dma_allocator.crypto.authsize);
    aead_request_set_crypt(disagg_dma_allocator.crypto.req, sg_src, sg_dst, size, disagg_dma_allocator.crypto.iv);
    if (crypto_wait_req(crypto_aead_encrypt(disagg_dma_allocator.crypto.req), &disagg_dma_allocator.crypto.wait)) {
	pr_err("disagg_dma_encrypt: encryption failed\n");
	return 1;
    }
     
    ++(*disagg_dma_allocator.crypto.counter);

#ifdef CONFIG_DISAGG_DEBUG_DMA_SEC
    pr_info("cipher-size (only encrypted data): %ld\n", size);
    my_print_hexdump("ciphertext: ", to, size);
    my_print_hexdump("Auth tag: ", to + size, disagg_dma_allocator.crypto.authsize);
    pr_info("\n");
#endif

    return 0;
}

static int disagg_dma_decrypt(void *from, void *to, size_t size)
{
    struct scatterlist sg_src[1];
    struct scatterlist sg_dst[1];
    int err;

#ifdef CONFIG_DISAGG_DEBUG_DMA_SEC
    pr_info("disagg_dma_decrypt:\n");
    pr_info("counter: %llu", *disagg_dma_allocator.crypto.counter);
    pr_info("cipher-size (only encrypted data): %ld\n", size);
    my_print_hexdump("ciphertext: ", from, size);
    my_print_hexdump("Auth Tag: ", from + size, disagg_dma_allocator.crypto.authsize);
#endif

    sg_mark_end(sg_src);
    sg_mark_end(sg_dst);
    sg_set_buf(sg_src, from, size + disagg_dma_allocator.crypto.authsize);
    sg_set_buf(sg_dst, to, size);
    aead_request_set_crypt(disagg_dma_allocator.crypto.req, sg_src, sg_dst, size + disagg_dma_allocator.crypto.authsize, disagg_dma_allocator.crypto.iv);
    err = crypto_wait_req(crypto_aead_decrypt(disagg_dma_allocator.crypto.req), &disagg_dma_allocator.crypto.wait);
    if (err) {
	if (err == -EBADMSG) {
	    pr_err("disagg_dma_decrypt: Authetication failed\n");
	    return 1;
	}
	pr_err("disagg_dma_decrypt: decryption failed\n");
	return 1;
    }

#ifdef CONFIG_DISAGG_DEBUG_DMA_SEC
    my_print_hexdump("Plaintext: ", to, size);
    pr_info("\n");
#endif

    ++(*disagg_dma_allocator.crypto.counter);
    return 0;
}

/* Allocates a dmu buffer from the shmem region */
dma_addr_t disagg_dma_map_page_attrs(struct device *dev, struct page *page, size_t offset, size_t size, enum dma_data_direction dir, unsigned long attrs) 
{
    struct guest_message_header hdr;
    void *vmDMA = page_to_virt(page) + offset;
    void *vmShmem;
    dma_addr_t proxyDMA;
    u8 resp;

    pr_info("disagg_dma_map_page_attrs\n");

    if (disagg_dma_allocator.vmShmem_start == NULL) {
	    pr_err("disagg_dma_map_page_attrs: shared memory not yet ready\n");
	    goto error;
    }

    spin_lock(&disagg_dma_allocator.lock);

    // just a simple one page allocator
    if (size > disagg_dma_allocator.dma_area_size || disagg_dma_allocator.free == 0) {
	pr_err("disagg_dma_alloc: request not fullfillable");
	goto error;
    }
    proxyDMA = disagg_dma_allocator.proxyDMA_start;
    disagg_dma_allocator.free = 0;
    // end of allocator

    vmShmem = proxyDMA_to_vmShmem(proxyDMA);

    // Encrypt the data to shmem
    disagg_dma_encrypt(vmDMA, vmShmem, size);

    // Provide proxy with information where the encrypted data is placed into shmem
    hdr.address = proxyDMA;
    hdr.operation = DISAGG_DEV_OP_DMA_MAP;
    hdr.length = size;
    ivshmem_write(&hdr, sizeof(hdr), 0);

    // confirmation for completion of decryption
    ivshmem_read(&resp, 1, 0);

    spin_unlock(&disagg_dma_allocator.lock);

    pr_info("disagg_dma_map_page: dma_handle: 0x%llx\n", (uint64_t) proxyDMA);

    disagg_dma_allocator.entry.vmDMA = vmDMA;
    disagg_dma_allocator.entry.proxyDMA = proxyDMA;
    disagg_dma_allocator.entry.size = size;

    return proxyDMA;

error:
    spin_unlock(&disagg_dma_allocator.lock);
    disagg_dma_allocator.free = 1;
    pr_info("disagg_dma_map_page failed\n");
    return DMA_MAPPING_ERROR;
}

void disagg_dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size, enum dma_data_direction dir, unsigned long attrs)
{
    spin_lock(&disagg_dma_allocator.lock);

    if (disagg_dma_allocator.free == 1) {
	pr_err("disagg_dma_free: cannot free already freed buffer\n");
	goto error;
    }

    disagg_dma_allocator.free = 1;

error:
    spin_unlock(&disagg_dma_allocator.lock);
}

void disagg___dma_sync_single_for_cpu(struct device *dev, dma_addr_t proxyDMA, size_t size, enum dma_data_direction dir)
{
    struct disagg_dma_entry *entry = disagg_find_entry(proxyDMA, size);
    if (entry == NULL) {
	pr_info("disagg___dma_sync_single_for_cpu: no entry corresponding to the arguments\n");
	return;
    }

    struct guest_message_header hdr;
    u8 res;
    u64 offset = proxyDMA - entry->proxyDMA;

    pr_info("disagg___dma_sync_single_for_cpu\n");

    spin_lock(&disagg_dma_allocator.lock);

    // Provide proxy with information where to encrypt the data inside shmem to
    hdr.address = (u64) proxyDMA;
    hdr.operation = DISAGG_DEV_OP_DMA_ENC;
    hdr.length = size;
    ivshmem_write(&hdr, sizeof(hdr), 0);

    // Confirm completion of encryption
    ivshmem_read(&res, sizeof(res), 0);

    // Decrypt data into virtual address space
    disagg_dma_decrypt(proxyDMA_to_vmShmem(proxyDMA) + offset, entry->vmDMA + offset, size);

    spin_unlock(&disagg_dma_allocator.lock);

    return;
}

void disagg___dma_sync_single_for_device(struct device *dev, dma_addr_t proxyDMA, size_t size, enum dma_data_direction dir)
{
    struct disagg_dma_entry *entry = disagg_find_entry(proxyDMA, size);
    if (entry == NULL) {
	pr_info("disagg___dma_sync_single_for_device: no entry corresponding to the arguments\n");
	goto error;
    }

    struct guest_message_header hdr;
    u8 res;
    u64 offset = proxyDMA - entry->proxyDMA;

    pr_info("disagg___dma_sync_single_for_device\n");

    spin_lock(&disagg_dma_allocator.lock);
    
    // Encrypt data into virtual address space
    disagg_dma_encrypt(entry->vmDMA + offset, proxyDMA_to_vmShmem(proxyDMA) + offset, size);

    // Give proxy source address of decrypted data in shmem
    hdr.address = (u64) proxyDMA;
    hdr.operation = DISAGG_DEV_OP_DMA_DEC;
    hdr.length = size;
    ivshmem_write(&hdr, sizeof(hdr), 0);

    // Confirm completion of encryption
    ivshmem_read(&res, sizeof(res), 0);

    spin_unlock(&disagg_dma_allocator.lock);

    return;

error:
    spin_unlock(&disagg_dma_allocator.lock);
    pr_info("disagg___dma_sync_single_for_device failed\n");
}


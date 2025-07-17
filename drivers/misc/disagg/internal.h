#ifndef __DISAGG_INTERNAL_H__
#define __DISAGG_INTERNAL_H__

#include <linux/rbtree.h>
#include <linux/dma-direction.h>
#include <crypto/aead.h>
#include <linux/scatterlist.h>

int disagg_init_dma(u8 *key, int keylen);

/*
* Remote device MMIO tracking structures
*/
struct disagg_dev_mmio_tracker {
	struct rb_root root;
	spinlock_t lock;
};

struct disagg_dev_mmio_range {
	struct rb_node node;
	unsigned long start;
	unsigned long end;
};

struct mmio_message {
	/* 
	 * Operation type (OP_READ or OP_WRITE)
	 */
	u8 operation;

	/* 
	 * Memory address for the operation 
	 */ 
	u64 address;

	/* 
	 * Length of data to read or write 
	 */
	u64 length;

	/*
	 * Value in case of OP_WRITE
	 */
	u64 value;
} __attribute__((packed));

struct disagg_dev_ioremap_lookup {
	struct rb_root root;
	spinlock_t lock;
};

struct disagg_dev_ioremap_entry {
	unsigned long virt_addr;
	phys_addr_t phys_addr;
	size_t size;
	struct rb_node node;
};

#define DISAGG_DEV_OP_READ 0
#define DISAGG_DEV_OP_WRITE 1

/*
* One entry corresponds to one mapped dma region
*/
struct disagg_dma_entry {
	struct rb_node node;
	void *vmDMA; // start of this region
	u64 proxyDMA; // this value is enough to calculate vmShmem and proxyShmem
	size_t size;
};

/*
* Used to keep track of free/used dma regions
*/
struct memory_region {
	u64 proxyDMA;
	size_t size;
	struct list_head list;
};

/*
* Data used in crypto operations
*/
struct disagg_crypto {
	struct crypto_aead *tfm; // Handle to transformation object
	struct aead_request *req; // AEAD request which registers with the tfm object
	struct crypto_wait wait; // Used to make calls to crypto API synchronous
	size_t authsize;
	u8 *iv;
	u64 *counter; // for freshness, used as the iv
};

/*
* Data used in MMIO
*/
struct disagg_mmio_data {
	struct disagg_crypto crypto;
	struct scatterlist sg[3]; // used by both encryption and decryption
	struct scatterlist sg_enc[3]; // encryption output
	struct scatterlist sg_dec[2]; // decryption input
	u8 *buf_enc; // one-time allocated buffer for encryption output (including auth)
	u8 *buf_dec; // one-time allocated buffer for decryption input
	size_t size_buffers; // size of buffers (both have same size)
};

/*
* Data used in DMA
*/
struct disagg_dma_data {
	struct disagg_crypto crypto;
	void *vmShmem_start; // Virtual address of shmem mapping DMA starting point
	size_t dma_area_size; // Size in bytes available for DMA allocations in shmem
	u64 proxyDMA_start; // virtual starting address of proxie's unencrypted DMA region
	struct rb_root entry_root;
	spinlock_t lock;
	struct list_head free_list; // tracks the still available memory blocks; sorted after proxyDMA
};

/*
* @key for crypto functionality
*/
int disagg_init_mmio(u8 *key, int keylen);

void disagg_exit_mmio(void);

phys_addr_t disagg_ioremap_virt_to_phys(unsigned long virt_addr);

u64 disagg_ioremap_virt_to_offset(u64 virt_addr);

void disagg_ioremap_lookup_init(void);

void init_disagg_dev_mmio_tracker(void);

/*
 * Called by page-fault handler in disagg mmio read case
 */
int mmio_read(u64 size, u64 addr, unsigned long *val);

/*
 * Called by page-fault handler in disagg mmio write case
 */
int mmio_write(u64 size, u64 addr, unsigned long val);

#endif /* __DISAGG_INTERNAL_H__ */

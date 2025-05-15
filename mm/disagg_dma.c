#include <linux/mm.h>
#include <misc/qemu_ivshmem.h>

disagg_dma_allocator_t disagg_dma_allocator;

static int __init disagg_dma_allocator_init(void)
{
        disagg_dma_allocator.start = NULL;
	disagg_dma_allocator.dma_size = 0;
	disagg_dma_allocator.free = 0;
	spin_lock_init(&disagg_dma_allocator.lock);

	return 0;
}
core_initcall(disagg_dma_allocator_init);

/* Allocates a dmu buffer from the shmem region */
void *disagg_dma_alloc(struct device *dev, size_t size, dma_addr_t *dma_handle) 
{
    pr_info("disagg_dma_alloc\n");

    void *vadr;

    if (disagg_dma_allocator.start == NULL) {
	    pr_err("disagg_dma_alloc: shared memory not yet ready\n");
	    goto error;
    }

    spin_lock(&disagg_dma_allocator.lock);

    // just a simple one page allocator
    if (size > disagg_dma_allocator.dma_size || disagg_dma_allocator.free == 0) {
	pr_err("disagg_dma_alloc: request not fullfillable");
	goto error;
    }

    disagg_dma_allocator.free = 0;

    // read the dma address for the proxy into the handle (for now we assume sizeof(dma_addr_t) == 8)
    if (ivshmem_read_dma_proxy_address((void*) dma_handle, 8) < 8) {
	pr_err("disagg_dma_alloc: reading the proxy addr from shmem failed\n");
	goto error;
    }

    vadr = disagg_dma_allocator.start;

    spin_unlock(&disagg_dma_allocator.lock);

    pr_info("disagg_dma_alloc: cpu_addr: 0x%llx, dma_handle: 0x%llx\n", *(uint64_t *)vadr, *(uint64_t *)dma_handle);

    return vadr;

error:
    spin_unlock(&disagg_dma_allocator.lock);
    pr_info("disagg_dma_alloc failed\n");
    return NULL;
}

void disagg_dma_free(struct device *dev, size_t size, void *vadr, dma_addr_t dma_adr) {
    spin_lock(&disagg_dma_allocator.lock);

    if (disagg_dma_allocator.free == 1) {
	pr_err("disagg_dma_free: cannot free already freed buffer\n");
	goto error;
    }

    disagg_dma_allocator.free = 1;

error:
    spin_unlock(&disagg_dma_allocator.lock);
}


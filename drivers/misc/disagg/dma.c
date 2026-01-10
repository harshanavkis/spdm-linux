#include <crypto/aead.h>
#include <linux/scatterlist.h>
#include <linux/pci.h> // for dev_is_pci

#include <misc/qemu_ivshmem.h>
#include <linux/disagg.h>
#include "internal.h"

static struct disagg_dma_data ctx;

#ifdef HELLO //CONFIG_DISAGG_DEBUG_DMA_SEC
static void my_print_hexdump(const char *prefix, const void *buf, size_t len) {
    print_hex_dump(KERN_INFO, prefix, DUMP_PREFIX_NONE, 32, 1, buf, len, false);
}
#endif

static void *proxyDMA_to_vmShmem(u64 proxyDMA) {
    if (ctx.proxyDMA_start > (u64) ctx.vmShmem_start)
	return (void *) proxyDMA - ((void *)ctx.proxyDMA_start - ctx.vmShmem_start);
    else
	return (void *) proxyDMA + (ctx.vmShmem_start - (void *) ctx.proxyDMA_start);
}

/*
 * Removes the specified @size from @region 
 * If @size == @region->size then it removes the entry completely from the list
 * Expects that @size <= @region->size
 */
static void remove_region(struct memory_region *region, size_t size) {
    if (size == region->size) {
	list_del(&region->list);
	kfree(region);
    } else {
	region->size -= size;
	region->proxyDMA += size;
    }
}

/*
 * Searches for at least a @size long free area.
 * Just a simple first fit.
 * @return 0 for success
 * @return in @proxyDMA the address
 */
static int find_free_region(size_t size, dma_addr_t *proxyDMA) {

    struct list_head *crt = &ctx.free_list;
    
    if (list_empty(crt)) {
	pr_err("find_free_region: no buffer available");
	return 1;
    }

    size = PAGE_ALIGN(size); // Normally only used to align address, but should also work for this

    list_for_each(crt, &ctx.free_list) {
	struct memory_region *data = list_entry(crt, struct memory_region, list);
	
	if (data->size >= size) {
	    *proxyDMA = data->proxyDMA;
	    remove_region(data, size);
	    return 0;
	}
    }

    return 1;
}


/*
 * Looks for entry containing the specified range (addr, size)
 * @return NULL for no corresponding entry, the entry otherwise
 * (Many things copied from https://www.kernel.org/doc/html/latest/core-api/rbtree.html)
 */
static struct disagg_dma_entry *disagg_find_entry(dma_addr_t proxyDMA, size_t size)
{
    struct rb_node *crt_node = ctx.entry_root.rb_node;

    while (crt_node) {
	struct disagg_dma_entry *entry = container_of(crt_node, struct disagg_dma_entry, node);

	if (proxyDMA < entry->proxyDMA)
	    crt_node = crt_node->rb_left;
	else if (proxyDMA + size > entry->proxyDMA + entry->size)
	    crt_node = crt_node->rb_right;
	else 
	    return entry;
    }

    return NULL;
}

/*
 * Inserts the entry into the rb-tree.
 * Expects that the tree does not already contain an entry with this region.
 * (Many things copied from https://www.kernel.org/doc/html/latest/core-api/rbtree.html)
 */
static void disagg_insert_entry(struct disagg_dma_entry *new_entry)
{
    struct rb_node **crt = &(ctx.entry_root.rb_node);
    struct rb_node *parent = NULL;

    while (*crt) {
	struct disagg_dma_entry *data = container_of(*crt, struct disagg_dma_entry, node);
	parent = *crt;

	// This simple compare is enough as we expect the entry to be unique
	if (new_entry->proxyDMA < data->proxyDMA)
	    crt = &((*crt)->rb_left);
	else 
	    crt = &((*crt)->rb_right);
    }

    rb_link_node(&new_entry->node, parent, crt);
    rb_insert_color(&new_entry->node, &ctx.entry_root);
}

/*
 * Adds the memory region (@proxyDMA, @size) to the free list.
 * Expects the region to not be in the list.
 * Inserts in a sorted manner.
 * Coalesces with neighbours if possible.
 */
static void add_region_to_free_list(u64 proxyDMA, size_t size) {
    struct list_head *next = &ctx.free_list; // will be the right/next neighbour; means the region has to be inserted before
    struct list_head *prev; // Will be the left/prev neighbour
    u8 set = 0; // Flag to indicate if the region is already inserted into the list, one way or another
    struct memory_region *next_region = NULL;
    struct memory_region *prev_region = NULL;
    size = PAGE_ALIGN(size); // Normally only used to align address, but should also work for this

    list_for_each(next, &ctx.free_list) {
	struct memory_region *data = list_entry(next, struct memory_region, list);

	if (data->proxyDMA > proxyDMA) {
	    // Found right spot
	    break; 
	}
    }

    prev = next->prev;

    // Now coalesce with the neighbours if possible
    // First previous, then next
    // I know those cascading ifs are terrible, but cannot think of another way right now. (TODO)
    if (!list_is_head(prev, &ctx.free_list)) {
	prev_region = list_entry(prev, struct memory_region, list);

	if (prev_region->proxyDMA + prev_region->size == proxyDMA) {
	    prev_region->size += size;

	    set = 1;
	}
    } 
    
    if (!list_is_head(next, &ctx.free_list)) {
	next_region = list_entry(next, struct memory_region, list);

	if (next_region->proxyDMA == proxyDMA + size) {
	    if (set == 1) {
		prev_region->size += next_region->size;
		list_del(next);
		kfree(next_region);
	    } else {
		next_region->size += size;
		next_region->proxyDMA = proxyDMA;
		set = 1;
	    }
	}
    }

    if (set == 0) {
	// No coalescing happened, insert it alone-standing
	struct memory_region *new = kmalloc(sizeof(struct memory_region), GFP_KERNEL);
	if (new == NULL) {
	    pr_err("kmalloc failed");
	    return;
	}

	new->proxyDMA = proxyDMA;
	new->size = size;
	list_add(&new->list, prev);
    }
}

dma_addr_t disagg_dma_map_page_attrs(struct device *dev, struct page *page, size_t offset, size_t size, enum dma_data_direction dir, unsigned long attrs) 
{
    struct disagg_dma_entry *new_entry;
    void *vmDMA = page_to_virt(page) + offset;
    void *vmShmem;
    dma_addr_t proxyDMA;

#ifdef CONFIG_DISAGG_DEBUG_DMA_SEC
    pr_info("disagg_dma_map_page_attrs\n");
#endif

    if (ctx.vmShmem_start == NULL) {
	    pr_err("disagg_dma_map_page_attrs: shared memory not yet ready\n");
	    return DMA_MAPPING_ERROR;
    }

    spin_lock(&ctx.lock);

    // just a simple one page allocator
    if (find_free_region(size, &proxyDMA) != 0) {
	pr_err("disagg_dma_map_page_attrs: request not fulfillable");
	goto error;
    }

    new_entry = kmalloc(sizeof(struct disagg_dma_entry), GFP_KERNEL);

    new_entry->vmDMA = vmDMA;
    new_entry->proxyDMA = proxyDMA;
    new_entry->size = size;

    disagg_insert_entry(new_entry);
    // end of allocator

    vmShmem = proxyDMA_to_vmShmem(proxyDMA);

    // Copy the data to shmem
    memcpy(vmShmem, vmDMA, size);

    spin_unlock(&ctx.lock);

#ifdef CONFIG_DISAGG_DEBUG_DMA_SEC
    pr_info("disagg_dma_map_page: dma_handle: 0x%llx\n", (uint64_t) proxyDMA);
#endif

    return proxyDMA;

error:
    spin_unlock(&ctx.lock);
    pr_info("disagg_dma_map_page failed\n");
    return DMA_MAPPING_ERROR;
}
EXPORT_SYMBOL(disagg_dma_map_page_attrs);

void disagg_dma_unmap_page_attrs(struct device *dev, dma_addr_t proxyDMA, size_t size, enum dma_data_direction dir, unsigned long attrs)
{
    struct disagg_dma_entry *entry;

    spin_lock(&ctx.lock);

    entry = disagg_find_entry(proxyDMA, size);

    if (entry == NULL) {
	pr_err("disagg_dma_free: cannot free non-existent dma buffer\n");
	goto error;
    }

    rb_erase(&entry->node, &ctx.entry_root);
    kfree(entry);

    add_region_to_free_list(proxyDMA, size); 

    spin_unlock(&ctx.lock);

    return;

error:
    spin_unlock(&ctx.lock);
}
EXPORT_SYMBOL(disagg_dma_unmap_page_attrs);

void disagg___dma_sync_single_for_cpu(struct device *dev, dma_addr_t proxyDMA, size_t size, enum dma_data_direction dir)
{
#ifdef CONFIG_DISAGG_DEBUG_DMA_SEC
    pr_info("disagg___dma_sync_single_for_cpu\n");
#endif

    u64 offset;
    struct disagg_dma_entry *entry;

    spin_lock(&ctx.lock);

    entry = disagg_find_entry(proxyDMA, size);
    if (entry == NULL) {
	pr_info("disagg___dma_sync_single_for_cpu: no entry corresponding to the arguments\n");
	goto error;
    }

    offset = proxyDMA - entry->proxyDMA;

    memcpy(entry->vmDMA + offset, proxyDMA_to_vmShmem(proxyDMA), size);

    spin_unlock(&ctx.lock);

    return;
error:
    spin_unlock(&ctx.lock);
}
EXPORT_SYMBOL(disagg___dma_sync_single_for_cpu);

void disagg___dma_sync_single_for_device(struct device *dev, dma_addr_t proxyDMA, size_t size, enum dma_data_direction dir)
{
#ifdef CONFIG_DISAGG_DEBUG_DMA_SEC
    pr_info("disagg___dma_sync_single_for_device\n");
#endif

    u64 offset;
    struct disagg_dma_entry *entry;

    spin_lock(&ctx.lock);

    entry = disagg_find_entry(proxyDMA, size);
    if (entry == NULL) {
	pr_info("disagg___dma_sync_single_for_device: no entry corresponding to the arguments\n");
	goto error;
    }

    offset = proxyDMA - entry->proxyDMA;
    
    memcpy(proxyDMA_to_vmShmem(proxyDMA), entry->vmDMA + offset, size);

    spin_unlock(&ctx.lock);

    return;

error:
    spin_unlock(&ctx.lock);
    pr_info("disagg___dma_sync_single_for_device failed\n");
}
EXPORT_SYMBOL(disagg___dma_sync_single_for_device);

void *disagg_dma_alloc_attrs(struct device *dev, size_t size, dma_addr_t *dma_handle)
{
    struct disagg_dma_entry *new_entry;
    dma_addr_t proxyDMA;

#ifdef CONFIG_DISAGG_DEBUG_DMA_SEC
    pr_info("disagg_dma_alloc_attrs\n");
#endif

    if (ctx.vmShmem_start == NULL) {
	    pr_err("disagg_dma_map_page_attrs: shared memory not yet ready\n");
	    return NULL;
    }

    spin_lock(&ctx.lock);

    // just a simple one page allocator
    if (find_free_region(size, &proxyDMA) != 0) {
	pr_err("disagg_dma_alloc_attrs: request not fulfillable");
	goto error;
    }

    new_entry = kmalloc(sizeof(struct disagg_dma_entry), GFP_KERNEL);

    new_entry->proxyDMA = proxyDMA;
    new_entry->vmDMA = proxyDMA_to_vmShmem(proxyDMA);
    new_entry->size = size;

    *dma_handle = proxyDMA;

    disagg_insert_entry(new_entry);
    // end of allocator

    spin_unlock(&ctx.lock);

#ifdef CONFIG_DISAGG_DEBUG_DMA_SEC
    pr_info("disagg_dma_alloc_attrs: dma_handle: 0x%llx\n", (uint64_t) proxyDMA);
#endif

    return new_entry->vmDMA;

error:
    spin_unlock(&ctx.lock);
    pr_info("disagg_dma_alloc_attrs failed\n");
    return NULL;
}
EXPORT_SYMBOL(disagg_dma_alloc_attrs);

void disagg_dma_free_attrs(struct device *dev, size_t size, void *cpu_addr, dma_addr_t proxyDMA)
{
    struct disagg_dma_entry *entry;

    spin_lock(&ctx.lock);

    entry = disagg_find_entry(proxyDMA, size);

    if (entry == NULL) {
	pr_err("disagg_dma_free_attrs: cannot free non-existent dma buffer\n");
	goto error;
    }

    rb_erase(&entry->node, &ctx.entry_root);
    kfree(entry);

    add_region_to_free_list(proxyDMA, size); 

    spin_unlock(&ctx.lock);

    return;

error:
    spin_unlock(&ctx.lock);
}
EXPORT_SYMBOL(disagg_dma_free_attrs);

bool disagg_test_check_dma_values(size_t nodes, size_t idx, size_t size_at_idx) {
    if (list_count_nodes(&ctx.free_list) != nodes) {
	pr_err("disagg_test_check_dma_values: failed for nodes; expected: %lu, actual: %lu", nodes, list_count_nodes(&ctx.free_list));
       return false;	
    }

    struct list_head *pos;
    for (pos = ctx.free_list.next; idx > 0; --idx, pos = pos->next) { }

    struct memory_region *region = list_entry(pos, struct memory_region, list);
    if (region->size != size_at_idx) {
	pr_err("disagg_test_check_dma_values: failed for size_at_idx; expected: %lu, actual: %lu", size_at_idx, region->size);
       return false;	
    }
    
    return true;
}
EXPORT_SYMBOL(disagg_test_check_dma_values);

int disagg_init_dma(u8 *key, int keylen)
{
	pr_info("ctx_init");
	ctx.entry_root = RB_ROOT;
	INIT_LIST_HEAD(&ctx.free_list);
	spin_lock_init(&ctx.lock);

	// Set the remaining fields in ctx
	ctx.vmShmem_start = get_shmem() + DMA_REGION_OFFSET;
	ctx.dma_area_size = DMA_SIZE;

	// Reads proxies DMA address from shmem
	// This address can then be used to convert from proxyDMA to vmShmem
	ivshmem_read_nonblocking(&ctx.proxyDMA_start, sizeof(ctx.proxyDMA_start), OFFSET_PROXY_DMA);

	// Add the initial free memory region, which contains the whole free dma area
	struct memory_region *first_region = kmalloc(sizeof(struct memory_region), GFP_KERNEL);
	if (first_region == NULL) {
	    pr_err("disagg_dma_init: kmalloc failed");
	    goto error_free_aead;
	}
	first_region->proxyDMA = ctx.proxyDMA_start;
	first_region->size = ctx.dma_area_size;
	list_add(&first_region->list, &ctx.free_list);

	return 0;

error_free_aead:
	return 1;
}


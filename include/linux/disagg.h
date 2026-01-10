#ifndef __LINUX_DISAGG_H__
#define __LINUX_DISAGG_H__

#include <linux/device.h>

/*
 * @return true if @dev is the disaggragated device
 */
bool disagg_is_dev(struct device *dev);

/********************************************************/
/**************** Disagg device MMIO-API ****************/

int add_disagg_dev_mmio_range(unsigned long start, unsigned long end);

void disagg_register_ioremap(unsigned long virt_addr, phys_addr_t phys_addr, size_t size);

void disagg_dev_mark_page_not_present(unsigned long start_addr, size_t size);

/*
 * Handles page fault for disagg MMIO case.
 * Leads to execution of MMIO instruction
 */
void disagg_mmio_fault_handler(struct pt_regs *regs, unsigned long hw_error_code, unsigned long address);

/*
 * @return true if this address is part of a disagg dev MMIO region
 */
bool disagg_is_tracked_mmio(unsigned long addr);

/*
 * @return true if (@addr, @size) is a BAR from disaggregated device
 */
bool disagg_is_dev_addr(resource_size_t phys_addr, unsigned long size);


/********************************************************/
/***************** Disagg device DMA-API ****************/

/*
 * Hook for dma_map_page_attrs
 */
dma_addr_t disagg_dma_map_page_attrs(struct device *dev,
				     struct page *page,
				     size_t offset,
				     size_t size,
				     enum dma_data_direction dir,
				     unsigned long attrs);

/*
 * Hook for dma_unmap_page_attrs
 */
void disagg_dma_unmap_page_attrs(struct device *dev,
				 dma_addr_t addr,
				 size_t size,
				 enum dma_data_direction dir,
				 unsigned long attrs);

/*
 * Hook for __dma_sync_single_for_cpu
 */
void disagg___dma_sync_single_for_cpu(struct device *dev,
				      dma_addr_t addr,
				      size_t size,
				      enum dma_data_direction dir);

/*
 * Hook into __dma_sync_single_for_device
 */
void disagg___dma_sync_single_for_device(struct device *dev,
					 dma_addr_t addr,
					 size_t size,
					 enum dma_data_direction dir);

/*
 * Hook into dma_alloc_attrs
 */
void *disagg_dma_alloc_attrs(struct device *dev, size_t size, dma_addr_t *dma_handle);

/*
 * Hook into dma_free_attrs
 */
void disagg_dma_free_attrs(struct device *dev, size_t size, void *cpu_addr, dma_addr_t dma_handle);

/*
 * A testing function to check if the dma allocator has the expected values.
 * @nodes are the expected number of nodes contained in the free_list.
 * @idx specifies the list entry which should be of @size_at_idx.
 * @return true for every value as expected, false otherwise
 */
bool disagg_test_check_dma_values(size_t nodes, size_t idx, size_t size_at_idx);


#endif /* __LINUX_DISAGG_H__ */

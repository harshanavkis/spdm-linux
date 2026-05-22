#ifndef _MISC_QEMU_IVSHMEM_H_
#define _MISC_QEMU_IVSHMEM_H_

/*
 * Sized to fit JIGSAW_TRACE_MAX_BYTES (~14 MiB at present, see qemu_edu/
 * traces.h) plus the 4 KiB reserved at DMA_REGION_OFFSET. The disagg DMA
 * allocator (drivers/misc/disagg/dma.c) carves DMA_SIZE out of this pool,
 * so SHMEM_SIZE caps the largest dma_alloc_coherent the qemu_edu driver
 * can satisfy. Must match the QEMU ivshmem -object size in
 * jigsaw-overall/scripts/run/vm.sh and the SHMEM_SIZE macro in every
 * Coyote sw/ shmem.hpp.
 */
#define SHMEM_SIZE (1 << 24)  // 16 MiB
#define READ_DOORBELL_OFFSET 0
#define WRITE_DOORBELL_OFFSET 1
#define DOORBELL_SIZE 1  // 1 byte for each doorbell
#define TOTAL_DOORBELL_SIZE (DOORBELL_SIZE * 2)
#define MMIO_REGION_OFFSET (24)
#define DMA_REGION_OFFSET (1 << 12) // 4K aligned
#define DMA_SIZE (SHMEM_SIZE - DMA_REGION_OFFSET)

/* Offsets in the shared memory with special values */
#define OFFSET_PROXY_DMA (256)

ssize_t ivshmem_mmio_region_read(void *buf, size_t count);
ssize_t ivshmem_read(void *buf, size_t count, loff_t offset);
ssize_t ivshmem_mmio_region_write(const void *buf, size_t count);
ssize_t ivshmem_read_nonblocking(void *buf, size_t count, loff_t offset);
size_t ivshmem_write_nonblocking(void *buf, size_t count, loff_t offset);

/*
 * @return the virtual address of mapped shmem
 */
void *get_shmem(void);

#endif /* _MISC_QEMU_IVSHMEM_H_ */

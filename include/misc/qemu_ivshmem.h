#ifndef _MISC_QEMU_IVSHMEM_H_
#define _MISC_QEMU_IVSHMEM_H_

#define SHMEM_SIZE (1 << 20)  // 1 MB, adjust as needed
#define READ_DOORBELL_OFFSET 0
#define WRITE_DOORBELL_OFFSET 1
#define DOORBELL_SIZE 1  // 1 byte for each doorbell
#define TOTAL_DOORBELL_SIZE (DOORBELL_SIZE * 2)
#define DMA_PROXY_ADDRESS_OFFSET (256) // 8 Byte aligned and just far away from possible collision
#define DMA_REGION_OFFSET (1 << 12) // 4K aligned
#define DMA_SIZE (SHMEM_SIZE - DMA_REGION_OFFSET)

ssize_t ivshmem_read(void *buf, size_t count, loff_t offset);
ssize_t ivshmem_write(const void *buf, size_t count, loff_t offset);
ssize_t ivshmem_read_nonblocking(void *buf, size_t count, loff_t offset);

#endif /* _MISC_QEMU_IVSHMEM_H_ */

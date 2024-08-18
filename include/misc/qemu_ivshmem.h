#ifndef _MISC_QEMU_IVSHMEM_H_
#define _MISC_QEMU_IVSHMEM_H_

ssize_t ivshmem_read(void *buf, size_t count, loff_t offset);
ssize_t ivshmem_write(const void *buf, size_t count, loff_t offset);

#endif /* _MISC_QEMU_IVSHMEM_H_ */
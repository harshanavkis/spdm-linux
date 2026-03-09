// ivshmem_driver.c

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <misc/qemu_ivshmem.h>
#define DRIVER_NAME "ivshmem_driver"

struct ivshmem_dev {
	struct pci_dev *pdev;
	void __iomem *shmem;
	size_t shmem_size;
};

static struct ivshmem_dev *ivs_dev_global;

void *get_shmem(void)
{
	return ivs_dev_global->shmem;
}
EXPORT_SYMBOL(get_shmem);

static int ivshmem_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
    struct ivshmem_dev *ivs_dev;
    int err;

    ivs_dev = kzalloc(sizeof(*ivs_dev), GFP_KERNEL);
    if (!ivs_dev)
        return -ENOMEM;

    err = pci_enable_device(pdev);
    if (err)
        goto free_dev;

    err = pci_request_regions(pdev, DRIVER_NAME);
    if (err)
        goto disable_device;

    ivs_dev->shmem_size = pci_resource_len(pdev, 2);
    ivs_dev->shmem = pci_iomap(pdev, 2, ivs_dev->shmem_size);
    if (!ivs_dev->shmem) {
        err = -ENOMEM;
        goto release_regions;
    }

    ivs_dev->pdev = pdev;
    pci_set_drvdata(pdev, ivs_dev);
    ivs_dev_global = ivs_dev;

    pr_info("ivshmem: Shared memory size: %zu bytes\n", ivs_dev->shmem_size);

    return 0;

release_regions:
    pci_release_regions(pdev);
disable_device:
    pci_disable_device(pdev);
free_dev:
    kfree(ivs_dev);
    return err;
}

static void ivshmem_remove(struct pci_dev *pdev)
{
    struct ivshmem_dev *ivs_dev = pci_get_drvdata(pdev);

    pci_iounmap(pdev, ivs_dev->shmem);
    pci_release_regions(pdev);
    pci_disable_device(pdev);
    kfree(ivs_dev);

    ivs_dev_global = NULL;
}

static const struct pci_device_id ivshmem_ids[] = {
    { PCI_DEVICE(0x1af4, 0x1110) },  // QEMU ivshmem device
    { 0 }
};
MODULE_DEVICE_TABLE(pci, ivshmem_ids);

static struct pci_driver ivshmem_driver = {
    .name = DRIVER_NAME,
    .id_table = ivshmem_ids,
    .probe = ivshmem_probe,
    .remove = ivshmem_remove,
};

static void wait_for_read_doorbell_set(void)
{
    while (readb(ivs_dev_global->shmem + READ_DOORBELL_OFFSET) == 0)
        cpu_relax();
}

static void wait_for_write_doorbell_clear(void)
{
    while (readb(ivs_dev_global->shmem + WRITE_DOORBELL_OFFSET) != 0)
        cpu_relax();
}

// another shared memory read to a non-mmio region (no need for doorbells)
// does really read at offset (not at offset + TOTAL_DOORBELL_SIZE like the other read)
ssize_t ivshmem_read_nonblocking(void *buf, size_t count, loff_t offset)
{
    if (!ivs_dev_global || !ivs_dev_global->shmem)
        return -ENODEV;

    if (offset >= ivs_dev_global->shmem_size)
        return 0;

    if (offset + count > ivs_dev_global->shmem_size)
        count = ivs_dev_global->shmem_size - offset;

    memcpy(buf, ivs_dev_global->shmem + offset, count);

    return count;
}
EXPORT_SYMBOL(ivshmem_read_nonblocking);

size_t ivshmem_write_nonblocking(void *buf, size_t count, loff_t offset)
{
    if (!ivs_dev_global || !ivs_dev_global->shmem)
        return -ENODEV;

    if (offset >= ivs_dev_global->shmem_size)
        return -1;

    if (offset + count > ivs_dev_global->shmem_size)
        count = ivs_dev_global->shmem_size - offset;

    memcpy(ivs_dev_global->shmem + offset, buf, count);

    return count;
}
EXPORT_SYMBOL(ivshmem_write_nonblocking);

/* To be deleted */
ssize_t ivshmem_read(void *buf, size_t count, loff_t offset)
{
    if (!ivs_dev_global || !ivs_dev_global->shmem)
        return -ENODEV;

    wait_for_read_doorbell_set();

    memcpy(buf, ivs_dev_global->shmem + offset, count);

    writeb(0, ivs_dev_global->shmem + READ_DOORBELL_OFFSET);

    return count;
}
EXPORT_SYMBOL(ivshmem_read);
/**/

ssize_t ivshmem_mmio_region_read(void *buf, size_t count)
{
    if (!ivs_dev_global || !ivs_dev_global->shmem)
        return -ENODEV;

    wait_for_read_doorbell_set();

    memcpy(buf, ivs_dev_global->shmem + MMIO_REGION_OFFSET, count);

    writeb(0, ivs_dev_global->shmem + READ_DOORBELL_OFFSET);

    return count;
}
EXPORT_SYMBOL(ivshmem_mmio_region_read);


ssize_t ivshmem_mmio_region_write(const void *buf, size_t count)
{
    if (!ivs_dev_global || !ivs_dev_global->shmem)
        return -ENODEV;

    wait_for_write_doorbell_clear();

    memcpy(ivs_dev_global->shmem + MMIO_REGION_OFFSET, buf, count);

    writeb(1, ivs_dev_global->shmem + WRITE_DOORBELL_OFFSET);

    return count;
}
EXPORT_SYMBOL(ivshmem_mmio_region_write);

static int __init ivshmem_init(void)
{
	return pci_register_driver(&ivshmem_driver);
}

static void __exit ivshmem_exit(void)
{
	pci_unregister_driver(&ivshmem_driver);
}

module_init(ivshmem_init);
module_exit(ivshmem_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Harshavardhan Unnibhavi");
MODULE_DESCRIPTION("QEMU ivshmem PCI driver with polling synchronization");


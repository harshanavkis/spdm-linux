/* many things copied from  https://cirosantilli.com/linux-kernel-module-cheat#qemu-edu */
#include <linux/cdev.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/kernel.h>
#include <linux/device.h> // for dev_* debugging messages
#include <asm-generic/io.h> // for iowrite*/ioread*
#include <linux/timekeeping.h> // for time measurement
#include <linux/delay.h> // just to introduce test delay

#define QEMU_VENDOR_ID 0x1234
#define QEMU_EDU_DEVICE_ID 0x11e8
#define PCI_BAR 0
#define MY_DRIVER_NAME "my_qemu_edu_driver"
#define CDEV_NAME "my_qemu_edu"

/* Registers. */
#define IO_IRQ_STATUS 0x24
#define IO_IRQ_ACK 0x64
#define IO_DMA_SRC 0x80
#define IO_DMA_DST 0x88
#define IO_DMA_CNT 0x90
#define IO_DMA_CMD 0x98

/* Constants */
#define DMA_BASE 0x40000
#define DMA_CMD 0x1
#define DMA_FROM_DEV 0x2
#define DMA_IRQ 0x4


static int major;
static struct pci_dev *pdev;
static void __iomem *mmio;

static long dma_size = 4321;
module_param(dma_size, long, 0);
MODULE_PARM_DESC(dma_size, "The size of the buffer used in the DMA test");

static struct pci_device_id my_pci_ids[] = {
    { PCI_DEVICE(QEMU_VENDOR_ID, QEMU_EDU_DEVICE_ID) },
    { 0, }
};
MODULE_DEVICE_TABLE(pci, my_pci_ids);


/* Cdev file operations */

static ssize_t my_read(struct file *filep, char __user *buf, size_t len, loff_t *off)
{
    // use ioread* and copy_to_user
    return 0;
}

static ssize_t my_write(struct file *filep, const char __user *buf, size_t len, loff_t *off)
{
    // use iowrite* and copy_from_user
    return 0;
}

static struct file_operations my_fops = {
    .owner = THIS_MODULE,
    .read = my_read,
    .write = my_write,
};

/* Irq */

static irqreturn_t my_irq_handler(int irq, void *dev)
{
    int devi;
    irqreturn_t ret;
    u32 irq_status;

    devi = *(int *)dev;
    if (devi == major) {
	irq_status = ioread32(mmio + IO_IRQ_STATUS);
	pr_info("my_irq_handler irq = %d, dev = %d, irq_status = %llx\n",
		irq, devi, (unsigned long long) irq_status);
	iowrite32(irq_status, mmio + IO_IRQ_ACK);
	ret = IRQ_HANDLED;
    } else {
	ret = IRQ_NONE;
    }
    return ret;
}

/* Pci specific code */

/* https://www.kernel.org/doc/html/latest/PCI/pci.html#device-initialization-steps */
static int my_pci_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
    dev_info(&dev->dev, "my_pci_probe\n");

    pdev = dev;
    major = register_chrdev(0, CDEV_NAME, &my_fops);

    if (pci_enable_device(dev) < 0) {
	dev_err(&dev->dev, "Error: pci_enable_device failed\n");
	goto error;
    }

    if (pci_request_region(dev, PCI_BAR, MY_DRIVER_NAME) < 0) {
	dev_err(&dev->dev, "Error: pci_request_region failed\n");
	goto error_requ_reg;
    }

    mmio = pci_iomap(dev, PCI_BAR, pci_resource_len(dev, PCI_BAR));

    /* IRQ setup */
    pci_set_master(dev);

    if (pci_alloc_irq_vectors(dev, 1, 1, PCI_IRQ_MSI) < 0) {
	dev_err(&(dev->dev), "Error: pci_alloc_irq_vectors failed\n");
	goto error_irq_vectors;
    }

    dev->irq = pci_irq_vector(dev, 0);

    if (request_irq(dev->irq, my_irq_handler, 0, CDEV_NAME, &major) < 0) {
	dev_err(&(dev->dev), "Error: request_irq failed\n");
	goto error_requ_irq;
    }

    {
	// Benchmarks 
	// Do one single dma_map_single with the buffer size of parameter @dma_size
	pr_info("param size input: %lu", dma_size);

	ktime_t start, end;
	dma_addr_t dma_handle;
	void *actual = kmalloc(dma_size, GFP_KERNEL);
	if (actual == NULL) {
	    pr_info("kmalloc failed");
	    return 0;
	}

	memset(actual, 0xba, dma_size);

	start = ktime_get();
	dma_handle = dma_map_single(&(dev->dev), actual, dma_size, DMA_BIDIRECTIONAL);
	end = ktime_get();

	if (dma_mapping_error(&(dev->dev), dma_handle)) {
	    dev_info(&(dev->dev), "my_pci_probe: dma_alloc_coherent failed\n");
	    return 0;
	}

	dma_unmap_single(&(dev->dev), dma_handle, dma_size, DMA_BIDIRECTIONAL);
	kfree(actual);

	pr_info("time measured: %lu;%llu end", dma_size, (u64) ktime_to_ns(end) - (u64) ktime_to_ns(start));
    }

    return 0;

error_requ_irq:
    pci_free_irq_vectors(dev);
error_irq_vectors:
    pci_iounmap(dev, mmio);
    pci_release_region(dev, PCI_BAR);
error_requ_reg:
    pci_disable_device(dev);
error:
    return 1;
}

static void my_pci_remove(struct pci_dev *dev)
{
    dev_info(&dev->dev, "my_pci_remove\n");
    free_irq(pci_irq_vector(dev, 0), &major);
    pci_free_irq_vectors(dev);
    pci_iounmap(dev, mmio);
    pci_disable_device(dev);
    pci_release_region(dev, PCI_BAR); /* has to be called after disabling device */
    unregister_chrdev(major, CDEV_NAME);
}


static struct pci_driver my_pci_driver = {
    .name = MY_DRIVER_NAME,
    .id_table = my_pci_ids,
    .probe = my_pci_probe,
    .remove = my_pci_remove,
};


/* Module handling */
static int __init my_init(void)
{
    if (pci_register_driver(&my_pci_driver) < 0) {
	pr_err("my_init: pci_reigster_driver failed\n");
	return 1;
    }
    return 0;
}

static void __exit my_exit(void)
{
    pci_unregister_driver(&my_pci_driver);
};

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Driver for the qemu EDU device");
module_init(my_init);
module_exit(my_exit);

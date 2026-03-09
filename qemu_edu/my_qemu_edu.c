/* many things copied from  https://cirosantilli.com/linux-kernel-module-cheat#qemu-edu */
#include <linux/cdev.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/kernel.h>
#include <linux/device.h> // for dev_* debugging messages
#include <asm-generic/io.h> // for iowrite*/ioread*
#include <linux/mm.h> // for disagg_test_check_dma_values
#include <linux/disagg.h>

#define QEMU_VENDOR_ID 0x1234
#define QEMU_EDU_DEVICE_ID 0x11e8
#define PCI_BAR 0
#define MY_DRIVER_NAME "my_qemu_edu_driver"
#define CDEV_NAME "my_qemu_edu"

/* Registers. */
#define DMA_CMD_REG 0x00
#define DMA_SRC_ADDR_REG 0x08
#define DMA_DST_ADDR_REG 0x10
#define DMA_LEN_REG 0x18
#define DMA_STATUS_REG 0x20
#define START_COMPUTATION_REG 0x28

/* Constants */
#define DMA_CMD 0x1
#define DMA_FROM_DEV 0x2


static int major;
static struct pci_dev *pdev;
static void __iomem *mmio;

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

	pci_set_master(dev);

	/* Optional sanity checks. The PCI is ready now, all of this could also be called from fops. */
	{

		/* Check that we are using MEM instead of IO.
		 *
		 * In QEMU, the type is defiened by either:
		 *
		 * - PCI_BASE_ADDRESS_SPACE_IO
		 * - PCI_BASE_ADDRESS_SPACE_MEMORY
		 */
		if ((pci_resource_flags(dev, PCI_BAR) & IORESOURCE_MEM) != IORESOURCE_MEM) {
			dev_err(&(dev->dev), "pci_resource_flags\n");
			goto error;
		}

		/* 1Mb, as defined by the "1 << 20" in QEMU's memory_region_init_io. Same as pci_resource_len. */
		resource_size_t start = pci_resource_start(dev, PCI_BAR);
		resource_size_t end = pci_resource_end(dev, PCI_BAR);
		pr_info("The starting address of BAR %d is %lx\n", PCI_BAR, (unsigned long)(start));
		pr_info("length %llx\n", (unsigned long long)(end + 1 - start));
		pr_info("EDU MMIO virtual address starts at: %lx\n", (unsigned long) mmio);

		pr_info("QEMU EDU: Address: %llu\n", virt_to_phys(mmio));

		/* Tests */
#define DMA_CMD_REG 0x00
#define DMA_SRC_ADDR_REG 0x08
#define DMA_DST_ADDR_REG 0x10
#define DMA_LEN_REG 0x18
#define DMA_STATUS_REG 0x20
#define START_COMPUTATION_REG 0x28
		{
			dev_info(&(dev->dev), "Test 1\n");

			// Test src addr register
			u64 val_src_addr = 0x1234567;
			writeq(val_src_addr, mmio + DMA_SRC_ADDR_REG);

			if (readq(mmio + DMA_SRC_ADDR_REG) != val_src_addr) {
				pr_info("src addr Value does not match! Expected: %llx, got : %llx\n", val_src_addr, readq(mmio + DMA_SRC_ADDR_REG));
				return 0;
			}

			// Test dst addr register
			u64 val_dst_addr = 0x983235;
			writeq(val_dst_addr, mmio + DMA_DST_ADDR_REG);

			if (readq(mmio + DMA_DST_ADDR_REG) != val_dst_addr) {
				pr_info("dst addr Value does not match! Expected: %llx, got : %llx\n", val_dst_addr, readq(mmio + DMA_DST_ADDR_REG));
				return 0;
			}

			// Test len register
			u64 val_len = 0x983235;
			writeq(val_len, mmio + DMA_LEN_REG);

			if (readq(mmio + DMA_LEN_REG) != val_len) {
				pr_info("Len Value does not match! Expected: %llx, got : %llx\n", val_len, readq(mmio + DMA_LEN_REG));
				return 0;
			}

			{
				// Do a H2D Dma transfer
				dev_info(&(dev->dev), "DMA Test 1\n");
				dma_addr_t dma_handle;
				enum { SIZE = 256 };
				void *actual;


				actual = dma_alloc_coherent(&(dev->dev), SIZE, &dma_handle, 0);
				if (!actual) {
					dev_info(&(dev->dev), "my_pci_probe: dma_alloc_coherent failed\n");
					return 0;
				}

				memset(actual, 0xba, SIZE);

				// Proide device with information about the DMA transfer
				writeq((u64)dma_handle, mmio + DMA_SRC_ADDR_REG);
				writeq(SIZE, mmio + DMA_LEN_REG);
				writeq(DMA_CMD, mmio + DMA_CMD_REG);
				while(!(readq(mmio + DMA_STATUS_REG) & 0x1)) {}

				dma_free_coherent(&(dev->dev), SIZE, actual, dma_handle);
			}

			{
				// Do a bigger H2D Dma transfer
				dev_info(&(dev->dev), "DMA Test 2\n");
				dma_addr_t dma_handle;
				enum { SIZE = 2 << 17 };
				void *actual;


				actual = dma_alloc_coherent(&(dev->dev), SIZE, &dma_handle, 0);
				if (!actual) {
					dev_info(&(dev->dev), "my_pci_probe: dma_alloc_coherent failed\n");
					return 0;
				}

				memset(actual, 0xba, SIZE);

				// Proide device with information about the DMA transfer
				writeq((u64)dma_handle, mmio + DMA_SRC_ADDR_REG);
				writeq(SIZE, mmio + DMA_LEN_REG);
				writeq(DMA_CMD, mmio + DMA_CMD_REG);
				while(!(readq(mmio + DMA_STATUS_REG) & 0x1)) {}

				dma_free_coherent(&(dev->dev), SIZE, actual, dma_handle);
			}

			{
				// Do a D2H Dma transfer
				dev_info(&(dev->dev), "DMA Test 3\n");
				dma_addr_t dma_handle;
				enum { SIZE = 256 };
				void *actual;


				actual = dma_alloc_coherent(&(dev->dev), SIZE, &dma_handle, 0);
				if (!actual) {
					dev_info(&(dev->dev), "my_pci_probe: dma_alloc_coherent failed\n");
					return 0;
				}

				memset(actual, 0xba, SIZE);

				// Proide device with information about the DMA transfer
				writeq((u64)dma_handle, mmio + DMA_DST_ADDR_REG);
				writeq(SIZE, mmio + DMA_LEN_REG);
				writeq(DMA_CMD + DMA_FROM_DEV, mmio + DMA_CMD_REG);
				while(!(readq(mmio + DMA_STATUS_REG) & 0x1)) {}

				dma_free_coherent(&(dev->dev), SIZE, actual, dma_handle);
			}

		}

	}
	return 0;

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

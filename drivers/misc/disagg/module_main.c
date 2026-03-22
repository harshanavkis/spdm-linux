#include <linux/module.h>
#include <linux/pci.h>

#include <linux/disagg.h>
#include "internal.h"

bool disagg_is_dev(struct device *dev) 
{
	struct pci_dev *pdev;

	if (dev_is_pci(dev))
		pdev = container_of(dev, struct pci_dev, dev);
	else
		return false;

	if (unlikely((pdev->vendor == DISAGG_VENDOR_ID) && (pdev->device == DISAGG_DEVICE_ID)))
		return true;
	else
		return false;
	
}
EXPORT_SYMBOL(disagg_is_dev);

bool disagg_is_dev_addr(resource_size_t phys_addr, unsigned long size)
{
	struct pci_dev *pdev;
	struct resource res = { .start = phys_addr, .end = phys_addr + size - 1, .flags = IORESOURCE_MEM };
	bool ret = false;

	pdev = pci_get_device(DISAGG_VENDOR_ID, DISAGG_DEVICE_ID, NULL);

	if (!pdev)
		return false;

	if (!pci_find_resource(pdev, &res))
		ret = false;
	else 
		ret = true;

	pci_dev_put(pdev);
	return ret;
}
EXPORT_SYMBOL(disagg_is_dev_addr);

// Initialize the GCM AEAD objects
static int disagg_crypto_objects_init(void)
{
	int keylen = 32;
	u8 *key = kmalloc(keylen, GFP_KERNEL);
	if (!key) {
		pr_err("disagg_crypto_objects_init: kmalloc failed\n");
		return 1;
	}
	memset(key, 0x00, keylen); // init with dummy value

	if (disagg_init_mmio(key, keylen) != 0) {
		goto free_key;
	}

	if (disagg_init_dma(key, keylen) != 0) {
		goto free_key;
	}

	kfree(key);

	return 0;

free_key:
	kfree(key);
	return 1;
}

static int __init disagg_init(void)
{
	int ret;

	pr_info("disagg_init\n");

	ret = disagg_crypto_objects_init();
	if (ret != 0) {
		pr_err("disagg_init failed\n");
		return 1;
	}

	disagg_ioremap_lookup_init();
	init_disagg_dev_mmio_tracker();

	return 0;
}

static void __exit disagg_exit(void)
{
	pr_info("disagg_exit\n");

	disagg_exit_mmio();
}

/* Late because AES-NI has to be already init */
late_initcall(disagg_init);
module_exit(disagg_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Harshavardhan Unnibhavi & Maximilian Jaecklein");
MODULE_DESCRIPTION("Disaggregation implementation for shared memory");

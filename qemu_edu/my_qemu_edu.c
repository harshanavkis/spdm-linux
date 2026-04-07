/* many things copied from  https://cirosantilli.com/linux-kernel-module-cheat#qemu-edu */
#include <linux/cdev.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/kernel.h>
#include <linux/device.h>       // for dev_* debugging messages
#include <asm-generic/io.h>     // for iowrite*/ioread*
#include <linux/timekeeping.h>  // for ktime_get()
#include <linux/dma-mapping.h>  // for dma_alloc_coherent

#define QEMU_VENDOR_ID 0x1234
#define QEMU_EDU_DEVICE_ID 0x11e8
#define PCI_BAR 0
#define MY_DRIVER_NAME "my_qemu_edu_driver"
#define CDEV_NAME "my_qemu_edu"

/* Register used as MMIO benchmark target (64-bit R/W register) */
#define BENCH_REG_OFFSET 0x08

/* Custom DMA registers */
#define DMA_CMD_REG          0x00
#define DMA_SRC_ADDR_REG     0x08
#define DMA_DST_ADDR_REG     0x10
#define DMA_LEN_REG          0x18
#define DMA_STATUS_REG       0x20
#define START_COMPUTATION_REG 0x28
#define CYCLES_PER_COMPUTATION_REG 0x30

/* DMA constants */
#define DMA_CMD      0x1
#define DMA_FROM_DEV 0x2

#define NUM_RUNS 10

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
	return 0;
}

static ssize_t my_write(struct file *filep, const char __user *buf, size_t len, loff_t *off)
{
	return 0;
}

static struct file_operations my_fops = {
	.owner = THIS_MODULE,
	.read = my_read,
	.write = my_write,
};


/*
 * ============================================================
 * MMIO Benchmark
 *
 * Measures time for MMIO reads and writes at data sizes:
 *   1B, 2B, 4B, 8B, 16B, 32B, 64B
 *
 * Order: ALL writes first (all sizes, all runs), then ALL reads.
 * ============================================================
 */

static void do_mmio_write(int size, void __iomem *base)
{
	int j, num_ops;

	switch (size) {
	case 1:
		iowrite8(0xAB, base);
		break;
	case 2:
		iowrite16(0xABCD, base);
		break;
	case 4:
		iowrite32(0xABCD1234, base);
		break;
	case 8:
		writeq(0xABCD1234DEADBEEFULL, base);
		break;
	default:
		num_ops = size / 8;
		for (j = 0; j < num_ops; j++)
			writeq(0xABCD1234DEADBEEFULL, base);
		break;
	}
}

static void do_mmio_read(int size, void __iomem *base)
{
	volatile u8  s8;
	volatile u16 s16;
	volatile u32 s32;
	volatile u64 s64;
	int j, num_ops;

	switch (size) {
	case 1:
		s8 = ioread8(base);
		break;
	case 2:
		s16 = ioread16(base);
		break;
	case 4:
		s32 = ioread32(base);
		break;
	case 8:
		s64 = readq(base);
		break;
	default:
		num_ops = size / 8;
		for (j = 0; j < num_ops; j++)
			s64 = readq(base);
		break;
	}

	(void)s8; (void)s16; (void)s32; (void)s64;
}

static void run_mmio_benchmarks(struct pci_dev *dev)
{
	static const int data_sizes[] = {1, 2, 4, 8, 16, 32, 64};
	ktime_t start, end;
	u64 elapsed_ns;
	int i, run;

	pr_info("MMIO_BENCH_CSV: data_size,operation,time_ns,run_id\n");

	/* ---- ALL WRITES first ---- */
	for (i = 0; i < ARRAY_SIZE(data_sizes); i++) {
		int size = data_sizes[i];
		for (run = 0; run < NUM_RUNS; run++) {
			start = ktime_get();
			do_mmio_write(size, mmio + BENCH_REG_OFFSET);
			end = ktime_get();

			elapsed_ns = (u64)ktime_to_ns(end) - (u64)ktime_to_ns(start);
			pr_info("MMIO_BENCH_CSV: %d,write,%llu,%d\n",
				size, elapsed_ns, run);
		}
	}

	/* ---- ALL READS second ---- */
	for (i = 0; i < ARRAY_SIZE(data_sizes); i++) {
		int size = data_sizes[i];
		for (run = 0; run < NUM_RUNS; run++) {
			start = ktime_get();
			do_mmio_read(size, mmio + BENCH_REG_OFFSET);
			end = ktime_get();

			elapsed_ns = (u64)ktime_to_ns(end) - (u64)ktime_to_ns(start);
			pr_info("MMIO_BENCH_CSV: %d,read,%llu,%d\n",
				size, elapsed_ns, run);
		}
	}

	pr_info("MMIO_BENCH_CSV: mmio benchmark complete, %d total measurements\n",
		(int)ARRAY_SIZE(data_sizes) * 2 * NUM_RUNS);
}


/*
 * ============================================================
 * DMA Benchmark
 *
 * Measures time for DMA transfers at data sizes:
 *   4KiB, 8KiB, 16KiB, 32KiB, 64KiB, 128KiB, 256KiB, 512KiB, 1MiB
 *
 * Uses the custom DMA registers:
 *   DMA_SRC_ADDR_REG (0x08) - source host DMA address (H2D)
 *   DMA_DST_ADDR_REG (0x10) - destination host DMA address (D2H)
 *   DMA_LEN_REG      (0x18) - transfer length
 *   DMA_CMD_REG      (0x00) - start transfer (DMA_CMD for H2D,
 *                              DMA_CMD | DMA_FROM_DEV for D2H)
 *   DMA_STATUS_REG   (0x20) - poll bit 0 for completion
 *
 * Order: ALL H2D first (all sizes, all runs), then ALL D2H.
 * ============================================================
 */
static void run_dma_benchmarks(struct pci_dev *dev)
{
	/* 4K to 1M, doubling each time: 9 sizes */
	static const size_t dma_sizes[] = {
		4 * 1024,       /*   4 KiB */
		8 * 1024,       /*   8 KiB */
		16 * 1024,      /*  16 KiB */
		32 * 1024,      /*  32 KiB */
		64 * 1024,      /*  64 KiB */
		128 * 1024,     /* 128 KiB */
		256 * 1024,     /* 256 KiB */
		512 * 1024,     /* 512 KiB */
		1024 * 1024,    /*   1 MiB */
	};
	ktime_t start, mmio_done, end;
	u64 elapsed_ns, mmio_done_ns;
	int i, run;

	pr_info("DMA_BENCH_CSV: data_size,operation,total_time,mmio_done_ns,run_id,throughput_gibps\n");

	/* ---- ALL H2D first ---- */
	for (i = 0; i < ARRAY_SIZE(dma_sizes); i++) {
		size_t size = dma_sizes[i];
		dma_addr_t dma_handle;
		void *buf;

		buf = dma_alloc_coherent(&(dev->dev), size, &dma_handle, GFP_KERNEL);
		if (!buf) {
			pr_err("DMA_BENCH_CSV: dma_alloc_coherent failed for H2D size %zu\n", size);
			continue;
		}

		/* Fill buffer with a pattern */
		memset(buf, 0xAB, size);

		for (run = 0; run < NUM_RUNS; run++) {

			start = ktime_get();

			/* Program the custom DMA engine: host -> device */
			writeq((u64)dma_handle, mmio + DMA_SRC_ADDR_REG);

			writeq(size, mmio + DMA_LEN_REG);
			writeq(DMA_CMD, mmio + DMA_CMD_REG);
			mmio_done = ktime_get();

			/* Poll for completion */
			while (!(readq(mmio + DMA_STATUS_REG) & 0x1))
				;

			end = ktime_get();

			/* Clear status after polling */
			writeq(0, mmio + DMA_STATUS_REG);

			elapsed_ns = (u64)ktime_to_ns(end) - (u64)ktime_to_ns(start);
			mmio_done_ns = (u64)ktime_to_ns(mmio_done) - (u64)ktime_to_ns(start);
			{
				/* throughput = size / elapsed_s in GiB/s
				 * = size * 1e9 / (elapsed_ns * 2^30) */
				u64 tp_x1000 = (u64)size * 1000000000ULL * 1000ULL
					/ (elapsed_ns * 1073741824ULL);
				pr_info("DMA_BENCH_CSV: %zu,h2d,%llu,%llu,%d,%llu.%03llu\n",
					size, elapsed_ns, mmio_done_ns, run,
					tp_x1000 / 1000, tp_x1000 % 1000);
			}
		}

		dma_free_coherent(&(dev->dev), size, buf, dma_handle);
	}

	/* ---- ALL D2H second ---- */
	/* Note: device internal buffer already has data from the H2D phase above */
	for (i = 0; i < ARRAY_SIZE(dma_sizes); i++) {
		size_t size = dma_sizes[i];
		dma_addr_t dma_handle;
		void *buf;

		buf = dma_alloc_coherent(&(dev->dev), size, &dma_handle, GFP_KERNEL);
		if (!buf) {
			pr_err("DMA_BENCH_CSV: alloc failed for D2H size %zu\n", size);
			continue;
		}
		memset(buf, 0x00, size);


		for (run = 0; run < NUM_RUNS; run++) {
			start = ktime_get();

			/* Program the custom DMA engine: device -> host */
			writeq((u64)dma_handle, mmio + DMA_DST_ADDR_REG);

			writeq(size, mmio + DMA_LEN_REG);
			writeq(DMA_CMD | DMA_FROM_DEV, mmio + DMA_CMD_REG);
			mmio_done = ktime_get();

			/* Poll for completion */
			while (!(readq(mmio + DMA_STATUS_REG) & 0x1))
				;

			end = ktime_get();

			/* Clear status after polling */
			writeq(0, mmio + DMA_STATUS_REG);

			elapsed_ns = (u64)ktime_to_ns(end) - (u64)ktime_to_ns(start);
			mmio_done_ns = (u64)ktime_to_ns(mmio_done) - (u64)ktime_to_ns(start);
			{
				u64 tp_x1000 = (u64)size * 1000000000ULL * 1000ULL
					/ (elapsed_ns * 1073741824ULL);
				pr_info("DMA_BENCH_CSV: %zu,d2h,%llu,%llu,%d,%llu.%03llu\n",
					size, elapsed_ns, mmio_done_ns, run,
					tp_x1000 / 1000, tp_x1000 % 1000);
			}
		}

		dma_free_coherent(&(dev->dev), size, buf, dma_handle);
	}

	pr_info("DMA_BENCH_CSV: dma benchmark complete, %d total measurements\n",
		(int)ARRAY_SIZE(dma_sizes) * 2 * NUM_RUNS);
}

/*
 * ============================================================
 * Computation Benchmark
 *
 * Measures time for hardware computation at various cycle counts.
 * Uses:
 *   CYCLES_PER_COMPUTATION_REG (0x30) - set cycles
 *   START_COMPUTATION_REG      (0x28) - start (write 1 to bit 0)
 *   DMA_STATUS_REG             (0x20) - poll bit 1 (0x2) for completion
 * ============================================================
 */
static void run_comp_benchmarks(struct pci_dev *dev)
{
	static const size_t data_sizes[] = {
		4 * 1024,       /*   4 KiB */
		8 * 1024,       /*   8 KiB */
		16 * 1024,      /*  16 KiB */
		32 * 1024,      /*  32 KiB */
		64 * 1024,      /*  64 KiB */
		128 * 1024,     /* 128 KiB */
		256 * 1024,     /* 256 KiB */
		512 * 1024,     /* 512 KiB */
		1024 * 1024,    /*   1 MiB */
	};
	static const u64 comp_cycles[] = {
		100,
		1000,
		10000,
		100000,
		1000000,
	};
	ktime_t start, mmio_done, end;
	u64 total_time, mmio_done_ns;
	int i, j, run;

	pr_info("COMP_BENCH_CSV: data_size,cycles,operation,total_time,mmio_done_ns,run_id\n");

	for (i = 0; i < ARRAY_SIZE(data_sizes); i++) {
		size_t size = data_sizes[i];
		for (j = 0; j < ARRAY_SIZE(comp_cycles); j++) {
			u64 cycles = comp_cycles[j];

			for (run = 0; run < NUM_RUNS; run++) {
				start = ktime_get();

				/* Provide cycle count and start computation */
				writeq(cycles, mmio + CYCLES_PER_COMPUTATION_REG);
				writeq(1, mmio + START_COMPUTATION_REG);
				mmio_done = ktime_get();

				/* Poll for completion (bit 1 of DMA_STATUS_REG) */
				while (!(readq(mmio + DMA_STATUS_REG) & 0x2))
					;

				end = ktime_get();

				/* Clear status register (bits are latched, usually cleared by 0 write) */
				writeq(0, mmio + DMA_STATUS_REG);

				total_time = (u64)ktime_to_ns(end) - (u64)ktime_to_ns(start);
				mmio_done_ns = (u64)ktime_to_ns(mmio_done) - (u64)ktime_to_ns(start);

				pr_info("COMP_BENCH_CSV: %zu,%llu,comp,%llu,%llu,%d\n",
					size, cycles, total_time, mmio_done_ns, run);
			}
		}
	}

	pr_info("COMP_BENCH_CSV: computation benchmark complete\n");
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

	pci_set_master(dev);

	/* Sanity checks */
	{
		if ((pci_resource_flags(dev, PCI_BAR) & IORESOURCE_MEM) != IORESOURCE_MEM) {
			dev_err(&(dev->dev), "pci_resource_flags: not MEM\n");
			goto error;
		}

		resource_size_t start = pci_resource_start(dev, PCI_BAR);
		resource_size_t end = pci_resource_end(dev, PCI_BAR);
		pr_info("BAR %d start: %lx, length: %llx\n",
			PCI_BAR, (unsigned long)(start),
			(unsigned long long)(end + 1 - start));
		pr_info("EDU MMIO virtual address: %lx\n", (unsigned long)mmio);
	}

	/* Run benchmarks */
	run_mmio_benchmarks(dev);
	run_dma_benchmarks(dev);
	run_comp_benchmarks(dev);

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
MODULE_DESCRIPTION("MMIO and DMA benchmark driver for the QEMU EDU device");
module_init(my_init);
module_exit(my_exit);

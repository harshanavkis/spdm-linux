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
#include <linux/delay.h>
#include <asm/processor.h>

/*
 * The trace data lives in three auto-generated headers — small-traces.h,
 * medium-traces.h, long-traces.h — that all redefine the same symbols
 * (enum trace_kind, struct trace_event/app, JIGSAW_TRACE_MAX_BYTES,
 * tr_bfs[], jigsaw_traces[], etc.). To run all three back-to-back from
 * one TU we don't include any of them at file scope; instead, each is
 * included inside its own function body via run_*_trace_set() below, so
 * the static const arrays become function-local statics with no symbol
 * conflict. The file-scope mirror of the type layout lets a generic
 * replay routine consume any of them through a (const void *) cast.
 *
 * IMPORTANT: the file-scope layout below MUST match the auto-generated
 * struct in *-traces.h. If extract_traces.py changes the schema, update
 * the mirror here too.
 */

enum trace_kind {
	TRACE_BULK_H2D = 0,
	TRACE_BULK_D2H = 1,
	TRACE_BUNDLE   = 2,
};

struct trace_event {
	u8  kind;
	u64 h2d_size;
	u64 d2h_size;
	u64 cycles;
	int original_count;
};

struct trace_app {
	const char *name;
	const struct trace_event *events;
	size_t n;
};

/* Largest single transfer across all included sets — currently
 * long-traces.h's JIGSAW_TRACE_MAX_BYTES. Used to size the kernel-side
 * DMA buffer once, big enough for any of the three trace sets.
 *
 * The name deliberately differs from the header-supplied
 * JIGSAW_TRACE_MAX_BYTES, which gets #undef'd and redefined for each
 * function-scope #include below.
 */
#define MAX_TRACE_BUF_BYTES 14550656ULL

#define QEMU_VENDOR_ID 0x1234
#define QEMU_EDU_DEVICE_ID 0x11e8
#define PCI_BAR 0
#define MY_DRIVER_NAME "my_qemu_edu_driver"
#define CDEV_NAME "my_qemu_edu"

/* Register used as MMIO benchmark target (64-bit R/W register) */
#define BENCH_REG_OFFSET 0x08

/* Custom DMA registers (matches the emulated device payload_to_mmio ABI) */
#define DMA_CMD_REG          0x00
#define DMA_SRC_ADDR_REG     0x08
#define DMA_DST_ADDR_REG     0x10
#define DMA_H2D_LEN_REG      0x18
#define DMA_STATUS_REG       0x20
#define START_COMPUTATION_REG 0x28
#define CYCLES_PER_COMPUTATION_REG 0x30
#define DMA_TX_LEN_REG       0x38
#define DMA_D2H_LEN_REG      0x40

/* DMA constants */
#define DMA_CMD      0x1
#define DMA_FROM_DEV 0x2
#define DMA_DONE     0x1
#define COMPUTE_DONE 0x2
#define BUNDLE_DONE  (DMA_DONE | COMPUTE_DONE)

#define NUM_RUNS 10
#define TRACE_N_RUNS 5

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
 *   DMA_H2D_LEN_REG  (0x18) - host-to-device transfer length
 *   DMA_D2H_LEN_REG  (0x40) - device-to-host transfer length
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

			writeq(size, mmio + DMA_H2D_LEN_REG);
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

			writeq(size, mmio + DMA_D2H_LEN_REG);
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
 *   DMA_STATUS_REG             (0x20) - poll bits 0 and 1 (0x3) for completion
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
		dma_addr_t dma_handle;
		void *buf = dma_alloc_coherent(&(dev->dev), size, &dma_handle, GFP_KERNEL);
		if (!buf) {
			pr_err("COMP_BENCH_CSV: alloc failed for size %zu\n", size);
			continue;
		}
		memset(buf, 0x00, size);

		for (j = 0; j < ARRAY_SIZE(comp_cycles); j++) {
			u64 cycles = comp_cycles[j];

			for (run = 0; run < NUM_RUNS; run++) {
				start = ktime_get();

				writeq((u64)dma_handle, mmio + DMA_DST_ADDR_REG);
				writeq((u64)dma_handle, mmio + DMA_SRC_ADDR_REG);
				writeq(size, mmio + DMA_H2D_LEN_REG);
				writeq(size, mmio + DMA_D2H_LEN_REG);

				/* Provide cycle count and start computation */
				writeq(cycles, mmio + CYCLES_PER_COMPUTATION_REG);
				writeq(0, mmio + DMA_STATUS_REG);
				writeq(1, mmio + START_COMPUTATION_REG);
				mmio_done = ktime_get();

				/* Combined DMA+compute path completes when both bits are set. */
				while ((readq(mmio + DMA_STATUS_REG) & BUNDLE_DONE) != BUNDLE_DONE)
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

		dma_free_coherent(&(dev->dev), size, buf, dma_handle);
	}

	pr_info("COMP_BENCH_CSV: computation benchmark complete\n");
}


/*
 * ============================================================
 * Trace Replay
 *
 * Replays the bundled trace sets (small / medium / long), each baked into
 * its own header (small-traces.h, medium-traces.h, long-traces.h, all
 * generated by jigsaw-overall/scripts/extract_traces.py). The three sets
 * are run back-to-back in a single module load. Three event kinds:
 *
 *   TRACE_BULK_H2D : standalone H2D DMA (data preload, kernel binary).
 *   TRACE_BULK_D2H : standalone D2H DMA (final result readback).
 *   TRACE_BUNDLE   : one START_COMPUTATION_REG kick. The device does
 *                    H2D-in + busy-wait compute + D2H-out atomically.
 *
 * Output schema:
 *   TRACE_SUMMARY: set,app,run,n_events,n_bulk_h2d,n_bulk_d2h,n_bundle,
 *                  total_h2d_ns,total_d2h_ns,total_bundle_ns,total_ns,
 *                  total_h2d_bytes,total_d2h_bytes,total_cycles
 *   TRACE_EVENT:   set,app,run,event,kind,h2d_bytes,d2h_bytes,cycles
 *
 * The leading `set` column is "small", "medium", or "long".
 * ============================================================
 */

#define TRACE_DMA_OFFSET 4096ULL
#define MIN_DMA_BYTES 64ULL
#define TRACE_PAYLOAD_BYTES ((MAX_TRACE_BUF_BYTES + MIN_DMA_BYTES - 1) & ~(MIN_DMA_BYTES - 1))
#define TRACE_MEM_BYTES (TRACE_DMA_OFFSET + TRACE_PAYLOAD_BYTES)
#define TRACE_DMA_CAPACITY (TRACE_MEM_BYTES - TRACE_DMA_OFFSET)

/* BULK_H2D / BULK_D2H over the VM-path daemon hangs on single transfers
 * larger than ~1 MiB (root cause unidentified; suspected interaction
 * between the daemon's per-MMIO polling, host_controller MMIO arbitration,
 * and the device's RECEIVE_PAYLOAD pipeline). Sub-1-MiB transfers work
 * reliably, so we slice large bulks into back-to-back chunks at the kernel
 * level. The trace event line is still emitted with the original size; only
 * the actual MMIO sequence is split, so timing reflects the chunked cost.
 *
 * BUNDLE events are not chunked: the device's compute_engine completes a
 * single START_COMPUTE pulse, so there's no clean way to split. In practice
 * BUNDLE h2d/d2h are tiny (<256 B per traces.h's JIGSAW_BUNDLE_THRESHOLD)
 * and don't hit this limit anyway.
 */
#define TRACE_CHUNK_BYTES (1ULL << 20)  /* 1 MiB */

static u64 clamp_dma(u64 raw, u64 mem_cap)
{
	u64 sz = raw > mem_cap ? mem_cap : raw;
	/* Keep raw==0 as 0 so the device skips that phase entirely.
	 * Round non-zero sizes up to a cacheline multiple. */
	if (sz != 0) {
		sz = (sz + MIN_DMA_BYTES - 1) & ~(MIN_DMA_BYTES - 1);
		if (sz > mem_cap)
			sz = mem_cap & ~(MIN_DMA_BYTES - 1);
	}
	return sz;
}

static void replay_one(struct pci_dev *dev, const char *set_label,
		       const struct trace_app *app,
		       int run_idx, void *buf, dma_addr_t dma_handle)
{
	size_t i;
	ktime_t start, end;
	u64 total_ns;
	dma_addr_t trace_dma_handle = dma_handle + TRACE_DMA_OFFSET;
	int agg_n_bulk_h2d = 0, agg_n_bulk_d2h = 0, agg_n_bundle = 0;
	u64 agg_h2d_ns = 0, agg_d2h_ns = 0, agg_bundle_ns = 0;
	u64 agg_h2d_bytes = 0, agg_d2h_bytes = 0, agg_cycles = 0;

	for (i = 0; i < app->n; i++) {
		const struct trace_event *ev = &app->events[i];
		u64 h2d = 0, d2h = 0;

		switch (ev->kind) {
		case TRACE_BULK_H2D: {
			u64 remaining, off;
			h2d = clamp_dma(ev->h2d_size, TRACE_DMA_CAPACITY);
			pr_info("TRACE_EVENT: %s,%s,%d,%zu,%u,%llu,%llu,%llu\n",
				set_label, app->name, run_idx, i, ev->kind,
				(unsigned long long)h2d,
				(unsigned long long)d2h,
				(unsigned long long)ev->cycles);

			start = ktime_get();
			remaining = h2d;
			off = 0;
			while (remaining > 0) {
				u64 chunk = remaining > TRACE_CHUNK_BYTES
					? TRACE_CHUNK_BYTES : remaining;
				writeq((u64)trace_dma_handle + off, mmio + DMA_SRC_ADDR_REG);
				writeq((u64)trace_dma_handle + off, mmio + DMA_DST_ADDR_REG);
				writeq(chunk,           mmio + DMA_H2D_LEN_REG);
				writeq(0,               mmio + DMA_STATUS_REG);
				writeq(DMA_CMD,         mmio + DMA_CMD_REG);
				while (!(readq(mmio + DMA_STATUS_REG) & DMA_DONE))
					cpu_relax();
				writeq(0, mmio + DMA_STATUS_REG);
				off       += chunk;
				remaining -= chunk;
			}
			end = ktime_get();
			break;
		}

		case TRACE_BULK_D2H: {
			u64 remaining, off;
			d2h = clamp_dma(ev->d2h_size, TRACE_DMA_CAPACITY);
			pr_info("TRACE_EVENT: %s,%s,%d,%zu,%u,%llu,%llu,%llu\n",
				set_label, app->name, run_idx, i, ev->kind,
				(unsigned long long)h2d,
				(unsigned long long)d2h,
				(unsigned long long)ev->cycles);

			start = ktime_get();
			remaining = d2h;
			off = 0;
			while (remaining > 0) {
				u64 chunk = remaining > TRACE_CHUNK_BYTES
					? TRACE_CHUNK_BYTES : remaining;
				writeq((u64)trace_dma_handle + off, mmio + DMA_SRC_ADDR_REG);
				writeq((u64)trace_dma_handle + off, mmio + DMA_DST_ADDR_REG);
				writeq(chunk,           mmio + DMA_D2H_LEN_REG);
				writeq(0,               mmio + DMA_STATUS_REG);
				writeq(DMA_CMD | DMA_FROM_DEV, mmio + DMA_CMD_REG);
				while (!(readq(mmio + DMA_STATUS_REG) & DMA_DONE))
					cpu_relax();
				writeq(0, mmio + DMA_STATUS_REG);
				off       += chunk;
				remaining -= chunk;
			}
			end = ktime_get();
			break;
		}

		case TRACE_BUNDLE:
			h2d = clamp_dma(ev->h2d_size, TRACE_DMA_CAPACITY);
			d2h = clamp_dma(ev->d2h_size, TRACE_DMA_CAPACITY);
			pr_info("TRACE_EVENT: %s,%s,%d,%zu,%u,%llu,%llu,%llu\n",
				set_label, app->name, run_idx, i, ev->kind,
				(unsigned long long)h2d,
				(unsigned long long)d2h,
				(unsigned long long)ev->cycles);

			writeq(ev->cycles, mmio + CYCLES_PER_COMPUTATION_REG);

			start = ktime_get();
			writeq((u64)trace_dma_handle, mmio + DMA_SRC_ADDR_REG);
			writeq((u64)trace_dma_handle, mmio + DMA_DST_ADDR_REG);
			writeq(h2d,             mmio + DMA_H2D_LEN_REG);
			writeq(d2h,             mmio + DMA_D2H_LEN_REG);
			writeq(0,               mmio + DMA_STATUS_REG);
			writeq(1,               mmio + START_COMPUTATION_REG);
			while ((readq(mmio + DMA_STATUS_REG) & BUNDLE_DONE) != BUNDLE_DONE)
				cpu_relax();
			end = ktime_get();
			writeq(0, mmio + DMA_STATUS_REG);
			break;

		default:
			pr_warn("TRACE_CSV: %s run=%d skipping unknown kind %u at idx %zu\n",
				app->name, run_idx, ev->kind, i);
			continue;
		}

		total_ns = (u64)ktime_to_ns(end) - (u64)ktime_to_ns(start);

		switch (ev->kind) {
		case TRACE_BULK_H2D:
			agg_n_bulk_h2d++;
			agg_h2d_ns    += total_ns;
			agg_h2d_bytes += ev->h2d_size;
			break;
		case TRACE_BULK_D2H:
			agg_n_bulk_d2h++;
			agg_d2h_ns    += total_ns;
			agg_d2h_bytes += ev->d2h_size;
			break;
		case TRACE_BUNDLE:
			agg_n_bundle++;
			agg_bundle_ns += total_ns;
			agg_h2d_bytes += ev->h2d_size;
			agg_d2h_bytes += ev->d2h_size;
			agg_cycles    += ev->cycles;
			break;
		}
	}

	pr_info("TRACE_SUMMARY: %s,%s,%d,%zu,%d,%d,%d,%llu,%llu,%llu,%llu,%llu,%llu,%llu\n",
		set_label, app->name, run_idx, app->n,
		agg_n_bulk_h2d, agg_n_bulk_d2h, agg_n_bundle,
		agg_h2d_ns, agg_d2h_ns, agg_bundle_ns,
		agg_h2d_ns + agg_d2h_ns + agg_bundle_ns,
		(unsigned long long)agg_h2d_bytes,
		(unsigned long long)agg_d2h_bytes,
		(unsigned long long)agg_cycles);
}

/* Generic replay over a trace set described purely by the file-scope types.
 * apps_ptr is taken as void* because the wrappers below #include trace data
 * inside their own block scope, where the auto-generated header redefines
 * trace_event/trace_app as a (layout-identical) shadowing type — not the
 * file-scope types this function uses. Casting through void* sidesteps the
 * compiler's nominal type check; runtime field access is layout-correct.
 */
static void run_trace_set(struct pci_dev *dev, const char *set_label,
			  const void *apps_ptr, size_t n_apps,
			  void *buf, dma_addr_t dma_handle)
{
	const struct trace_app *apps = apps_ptr;
	size_t i;
	int run;

	pr_info("TRACE_CSV: starting set '%s' (%zu apps x %d runs)\n",
		set_label, n_apps, TRACE_N_RUNS);
	for (i = 0; i < n_apps; i++)
		for (run = 0; run < TRACE_N_RUNS; run++)
			replay_one(dev, set_label, &apps[i], run, buf, dma_handle);
	pr_info("TRACE_CSV: set '%s' complete (%zu apps x %d runs)\n",
		set_label, n_apps, TRACE_N_RUNS);
}

/* Each of the three wrappers below pulls its trace data into its own
 * function body via #include. The static const arrays inside each header
 * become function-local statics with no symbol clash, and the redefined
 * enum/struct definitions shadow the file-scope ones inside the block
 * (identical layout, different nominal types). #undef of the include
 * guard and the per-header macros lets the next wrapper include cleanly.
 */
static void run_small_trace_set(struct pci_dev *dev, void *buf, dma_addr_t dma_handle)
{
#undef JIGSAW_TRACES_H
#undef JIGSAW_TRACE_MAX_BYTES
#undef JIGSAW_BUNDLE_THRESHOLD
#include "small-traces.h"
	run_trace_set(dev, "small", (const void *)jigsaw_traces,
		      ARRAY_SIZE(jigsaw_traces), buf, dma_handle);
}

static void run_medium_trace_set(struct pci_dev *dev, void *buf, dma_addr_t dma_handle)
{
#undef JIGSAW_TRACES_H
#undef JIGSAW_TRACE_MAX_BYTES
#undef JIGSAW_BUNDLE_THRESHOLD
#include "medium-traces.h"
	run_trace_set(dev, "medium", (const void *)jigsaw_traces,
		      ARRAY_SIZE(jigsaw_traces), buf, dma_handle);
}

static void run_long_trace_set(struct pci_dev *dev, void *buf, dma_addr_t dma_handle)
{
#undef JIGSAW_TRACES_H
#undef JIGSAW_TRACE_MAX_BYTES
#undef JIGSAW_BUNDLE_THRESHOLD
#include "long-traces.h"
	run_trace_set(dev, "long", (const void *)jigsaw_traces,
		      ARRAY_SIZE(jigsaw_traces), buf, dma_handle);
}

static void run_trace_replay(struct pci_dev *dev)
{
	dma_addr_t dma_handle;
	void *buf;

	buf = dma_alloc_coherent(&(dev->dev), TRACE_MEM_BYTES,
				 &dma_handle, GFP_KERNEL);
	if (!buf) {
		pr_err("TRACE_CSV: dma_alloc_coherent failed (%llu bytes)\n",
		       (unsigned long long)TRACE_MEM_BYTES);
		return;
	}
	memset(buf, 0xAB, TRACE_MEM_BYTES);

	/* CSV header (column names match the per-event/per-summary lines). */
	pr_info("TRACE_EVENT: set,app,run,event,kind,h2d_bytes,d2h_bytes,cycles\n");
	pr_info("TRACE_SUMMARY: set,app,run,n_events,n_bulk_h2d,n_bulk_d2h,n_bundle,total_h2d_ns,total_d2h_ns,total_bundle_ns,total_ns,total_h2d_bytes,total_d2h_bytes,total_cycles\n");

	run_small_trace_set(dev, buf, dma_handle);
	run_medium_trace_set(dev, buf, dma_handle);
	run_long_trace_set(dev, buf, dma_handle);

	pr_info("TRACE_CSV: all trace sets complete\n");

	dma_free_coherent(&(dev->dev), TRACE_MEM_BYTES, buf, dma_handle);
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
	run_trace_replay(dev);

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

#include <asm/insn.h>
#include <asm/insn-eval.h>

#include "internal.h"
#include <linux/disagg.h>


struct disagg_dev_mmio_tracker disagg_mmio_tracker;

// Initialize the tracker
void init_disagg_dev_mmio_tracker(void)
{
	disagg_mmio_tracker.root = RB_ROOT;
	spin_lock_init(&disagg_mmio_tracker.lock);
}

struct disagg_dev_ioremap_lookup disagg_ioremap_lookup;

// Initialization function
void disagg_ioremap_lookup_init(void)
{
	disagg_ioremap_lookup.root = RB_ROOT;
	spin_lock_init(&disagg_ioremap_lookup.lock);
}

void disagg_register_ioremap(unsigned long virt_addr, phys_addr_t phys_addr, size_t size)
{
	struct disagg_dev_ioremap_entry *entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return;

	entry->virt_addr = virt_addr;
	entry->phys_addr = phys_addr;
	entry->size = size;

	spin_lock(&disagg_ioremap_lookup.lock);

	struct rb_node **new = &disagg_ioremap_lookup.root.rb_node, *parent = NULL;
	while (*new) {
		struct disagg_dev_ioremap_entry *this = rb_entry(*new, struct disagg_dev_ioremap_entry, node);
		parent = *new;

		if (virt_addr < this->virt_addr)
			new = &((*new)->rb_left);
		else if (virt_addr >= this->virt_addr + this->size)
			new = &((*new)->rb_right);
		else {
			spin_unlock(&disagg_ioremap_lookup.lock);
			kfree(entry);
			return; // Overlapping region, don't insert
		}
	}

	rb_link_node(&entry->node, parent, new);
	rb_insert_color(&entry->node, &disagg_ioremap_lookup.root);

	spin_unlock(&disagg_ioremap_lookup.lock);
}
EXPORT_SYMBOL(disagg_register_ioremap);

// Add a range to the tracker
int add_disagg_dev_mmio_range(unsigned long start, unsigned long end)
{
	struct disagg_dev_mmio_range *range = kmalloc(sizeof(struct disagg_dev_mmio_range), GFP_KERNEL);
	if (!range)
		return -ENOMEM;

	range->start = start;
	range->end = end;

	spin_lock(&disagg_mmio_tracker.lock);
	rb_link_node(&range->node, NULL, &disagg_mmio_tracker.root.rb_node);
	rb_insert_color(&range->node, &disagg_mmio_tracker.root);
	spin_unlock(&disagg_mmio_tracker.lock);

	return 0;
}
EXPORT_SYMBOL(add_disagg_dev_mmio_range);

/*
 * Mark pages between addr and addr + size as not present
*/
void disagg_dev_mark_page_not_present(unsigned long start_addr, size_t size)
{
	unsigned long addr, end_addr;
	pte_t *pte;
	unsigned int level;

	start_addr = PAGE_ALIGN(start_addr);
	end_addr = PAGE_ALIGN(start_addr + size);

	for (addr = start_addr; addr < end_addr; ) {
		pte = lookup_address(addr, &level);
		if (!pte) {
			pr_err("Failed to find PTE for address 0x%lx\n", addr);
			addr += PAGE_SIZE;
			continue;
		}

		if (level == PG_LEVEL_4K) {
			if (!pte_none(*pte)) {
				pte_clear(&init_mm, addr, pte);
#ifdef CONFIG_DISAGG_DEBUG_MMIO
				pr_info("Marked 4K page at 0x%lx as not present\n", addr);
#endif
				flush_tlb_one_kernel(addr);
			}
			addr += PAGE_SIZE;
		} else if (level == PG_LEVEL_2M) {
			pmd_t *pmd = (pmd_t *)pte;
			if (!pmd_none(*pmd)) {
				pmd_clear(pmd);
#ifdef CONFIG_DISAGG_DEBUG_MMIO
				pr_info("Marked 2M page at 0x%lx as not present\n", addr);
#endif
				flush_tlb_kernel_range(addr, addr + PMD_SIZE);
			}
			addr += PMD_SIZE;
		} else {
			pr_err("Unsupported page size for address 0x%lx (level %d)\n", addr, level);
			addr += PAGE_SIZE;
		}
	}
}

bool disagg_is_tracked_mmio(unsigned long addr)
{
	struct rb_node *node;
	bool ret = false;

	spin_lock(&disagg_mmio_tracker.lock);
	node = disagg_mmio_tracker.root.rb_node;

	while (node) {
		struct disagg_dev_mmio_range *range = rb_entry(node, struct disagg_dev_mmio_range, node);

		if (addr < range->start)
			node = node->rb_left;
		else if (addr > range->end)
			node = node->rb_right;
		else {
			ret = true;
			break;
		}
	}

	spin_unlock(&disagg_mmio_tracker.lock);
	return ret;
}
EXPORT_SYMBOL(disagg_is_tracked_mmio);

// As we assume, that the device has only one BAR we just return the offset.
// This offset provided to the device is enough to fulfill the request.
u64 disagg_ioremap_virt_to_offset(u64 virt_addr)
{
	struct rb_node *node;
	u64 offset = 0;

	spin_lock(&disagg_ioremap_lookup.lock);

	node = disagg_ioremap_lookup.root.rb_node;
	while (node) {
		struct disagg_dev_ioremap_entry *entry = rb_entry(node, struct disagg_dev_ioremap_entry, node);

		if (virt_addr < entry->virt_addr)
			node = node->rb_left;
		else if (virt_addr >= entry->virt_addr + entry->size)
			node = node->rb_right;
		else {
			offset = virt_addr - entry->virt_addr;
			break;
		}
	}

	spin_unlock(&disagg_ioremap_lookup.lock);

	return offset;
}

phys_addr_t disagg_ioremap_virt_to_phys(unsigned long virt_addr)
{
	struct rb_node *node;
	phys_addr_t phys_addr = 0;

	spin_lock(&disagg_ioremap_lookup.lock);

	node = disagg_ioremap_lookup.root.rb_node;
	while (node) {
		struct disagg_dev_ioremap_entry *entry = rb_entry(node, struct disagg_dev_ioremap_entry, node);

		if (virt_addr < entry->virt_addr)
			node = node->rb_left;
		else if (virt_addr >= entry->virt_addr + entry->size)
			node = node->rb_right;
		else {
			phys_addr = entry->phys_addr + (virt_addr - entry->virt_addr);
			break;
		}
	}

	spin_unlock(&disagg_ioremap_lookup.lock);

	return phys_addr;
}

void
disagg_mmio_fault_handler(struct pt_regs *regs, unsigned long hw_error_code, unsigned long address)
{
#ifdef CONFIG_DISAGG_DEBUG_MMIO
	pr_info("handle_page_fault: Caused by EDU disagg dev: %lu\n", address);
#endif

	unsigned long *reg, val;
	char buffer[MAX_INSN_SIZE];
	enum insn_mmio_type mmio;
	struct insn insn = {};
	int size, extend_size;
	u8 extend_val = 0;

#ifdef CONFIG_DISAGG_DEBUG_MMIO
	pr_info("disagg_mmio_fault_handler: iptr: %lu\n", regs->ip);
#endif

	if (copy_from_kernel_nofault(buffer, (void *)regs->ip, MAX_INSN_SIZE))
		pr_info("disagg_mmio_fault_handler: -EFAULT\n");
		// return -EFAULT;

	if (insn_decode(&insn, buffer, MAX_INSN_SIZE, INSN_MODE_64))
		pr_info("disagg_mmio_fault_handler: -EINVAL\n");
		// return -EINVAL;
	
#ifdef CONFIG_DISAGG_DEBUG_MMIO
	pr_info("opcode: 0x%x, 0x%x, 0x%x, 0x%x\n", insn.opcode.bytes[0], insn.opcode.bytes[1], insn.opcode.bytes[2], insn.opcode.bytes[3]);
#endif

	mmio = insn_decode_mmio(&insn, &size);

	if (WARN_ON_ONCE(mmio == INSN_MMIO_DECODE_FAILED))
		pr_info("disagg_mmio_fault_handler: insn_decode_mmio: -EINVAL\n");

	if (mmio != INSN_MMIO_WRITE_IMM && mmio != INSN_MMIO_MOVS) {
		reg = insn_get_modrm_reg_ptr(&insn, regs);
		if (!reg)
			pr_info("disagg_mmio_fault_handler: insn_get_modrm_reg_ptr: -EINVAL\n");
	}

	switch (mmio) {
	case INSN_MMIO_WRITE:
		memcpy(&val, reg, size);
		if (mmio_write(size, address, val) != 0)
			pr_info("disagg_mmio_fault_handler switch mmio: INSN_MMIO_WRITE_IMM: -EIO\n");
		regs->ip += insn.length;
		return;
	case INSN_MMIO_WRITE_IMM:
		val = insn.immediate.value;
		if (mmio_write(size, address, val) != 0)
			pr_info("disagg_mmio_fault_handler switch mmio: INSN_MMIO_WRITE_IMM: -EIO\n");
		regs->ip += insn.length;
		return;
	case INSN_MMIO_READ:
	case INSN_MMIO_READ_ZERO_EXTEND:
	case INSN_MMIO_READ_SIGN_EXTEND:
		/* Reads are handled below */
		break;
	case INSN_MMIO_MOVS:
	case INSN_MMIO_DECODE_FAILED:
		/*
		 * MMIO was accessed with an instruction that could not be
		 * decoded or handled properly. It was likely not using io.h
		 * helpers or accessed MMIO accidentally.
		 */
		pr_info("disagg_mmio_fault_handler switch mmio: INSN_MMIO_DECODE_FAILED: -EINVAL\n");
		return;
	default:
		WARN_ONCE(1, "Unknown insn_decode_mmio() decode value?");
		pr_info("disagg_mmio_fault_handler switch mmio: INSN_MMIO_DECODE_FAILED: -EINVAL\n");
		return;
	}

	switch (mmio) {
	case INSN_MMIO_READ:
	case INSN_MMIO_READ_ZERO_EXTEND:
	case INSN_MMIO_READ_SIGN_EXTEND:
		/* Reads are handled below */
		break;
	default:
		WARN_ONCE(1, "Unknown insn_decode_mmio() decode value?");
		pr_info("disagg_mmio_fault_handler switch mmio: -EINVAL\n");
		return;
	}

	if (mmio_read(size, address, &val) != 0)
		pr_info("disagg_mmio_fault_handler mmio_read: -EIO\n");

	switch (mmio) {
	case INSN_MMIO_READ:
		/* Zero-extend for 32-bit operation */
		extend_size = size == 4 ? sizeof(*reg) : 0;
		break;
	case INSN_MMIO_READ_ZERO_EXTEND:
		/* Zero extend based on operand size */
		extend_size = insn.opnd_bytes;
		break;
	case INSN_MMIO_READ_SIGN_EXTEND:
		/* Sign extend based on operand size */
		extend_size = insn.opnd_bytes;
		if (size == 1 && val & BIT(7))
			extend_val = 0xFF;
		else if (size > 1 && val & BIT(15))
			extend_val = 0xFF;
		break;
	default:
		/* All other cases has to be covered with the first switch() */
		WARN_ON_ONCE(1);
		pr_info("disagg_mmio_fault_handler extend reads: -EINVAL\n");
	}

	if (extend_size)
	{
		memset(reg, extend_val, extend_size);
#ifdef CONFIG_DISAGG_DEBUG_MMIO
		pr_info("disagg_mmio_fault_handler extend_size\n");
#endif
	}
	memcpy(reg, &val, size);

#ifdef CONFIG_DISAGG_DEBUG_MMIO
	pr_info("Copied val into register\n");
#endif
	
	regs->ip += insn.length;
#ifdef CONFIG_DISAGG_DEBUG_MMIO
	pr_info("Incremented instruction pointer: %u\n", insn.length);
	pr_info("disagg_mmio_fault_handler: iptr: %lu\n", regs->ip);
#endif

	if (copy_from_kernel_nofault(buffer, (void *)regs->ip, MAX_INSN_SIZE))
		pr_info("disagg_mmio_fault_handler: check iptr again: -EFAULT\n");
	
	if (insn_decode(&insn, buffer, MAX_INSN_SIZE, INSN_MODE_64))
		pr_info("disagg_mmio_fault_handler: decode iptr again: -EINVAL\n");

#ifdef CONFIG_DISAGG_DEBUG_MMIO
	pr_info("opcode: 0x%x, 0x%x, 0x%x, 0x%x\n", insn.opcode.bytes[0], insn.opcode.bytes[1], insn.opcode.bytes[2], insn.opcode.bytes[3]);
#endif
}


/*
 * Crash information logger
 * Copyright (C) 2010 Felix Fietkau <nbd@nbd.name>
 *
 * Based on ramoops.c
 *   Copyright (C) 2010 Marco Stornelli <marco.stornelli@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 */

#include <linux/module.h>
#include <linux/memblock.h>
#include <linux/debugfs.h>
#include <linux/crashlog.h>
#include <linux/kmsg_dump.h>
#include <linux/module.h>
#include <linux/pfn.h>
#include <linux/vmalloc.h>
#include <asm/io.h>

#define CRASHLOG_PAGES	4
#define CRASHLOG_SIZE	(CRASHLOG_PAGES * PAGE_SIZE)
#define CRASHLOG_MAGIC	0xa1eedead

/*
 * Start the log at 1M before the end of RAM, as some boot loaders like
 * to use the end of the RAM for stack usage and other things
 * If this fails, fall back to using the last part.
 */
#define CRASHLOG_OFFSET	(1024 * 1024)

struct crashlog_data {
	u32 magic;
	u32 len;
	u8 data[];
};

static struct debugfs_blob_wrapper crashlog_blob;
static unsigned long crashlog_addr = 0;
static struct crashlog_data *crashlog_buf;
static struct kmsg_dumper dump;
static bool first = true;

extern struct list_head *crashlog_modules;

static bool crashlog_set_addr(phys_addr_t addr, phys_addr_t size)
{
	/* Limit to lower 64 MB to avoid highmem */
	phys_addr_t limit = 64 * 1024 * 1024;

	if (crashlog_addr)
		return false;

	if (addr > limit)
		return false;

	if (addr + size > limit)
		size = limit - addr;

	crashlog_addr = addr;

	if (addr + size > CRASHLOG_OFFSET)
		crashlog_addr += size - CRASHLOG_OFFSET;

	return true;
}


void __init_memblock crashlog_init_memblock(phys_addr_t addr, phys_addr_t size)
{
	if (!crashlog_set_addr(addr, size))
		return;

	if (memblock_reserve(crashlog_addr, CRASHLOG_SIZE)) {
		printk("Crashlog failed to allocate RAM at address 0x%lx\n",
		       crashlog_addr);
		crashlog_addr = 0;
	}
}

static void __init crashlog_copy(void)
{
	if (crashlog_buf->magic != CRASHLOG_MAGIC) {
		printk("No crashlog found. Skipping Sysfs entry\n");
		return;
	}

	if (!crashlog_buf->len || crashlog_buf->len >
	    CRASHLOG_SIZE - sizeof(*crashlog_buf))
		return;

	crashlog_blob.size = crashlog_buf->len;
	crashlog_blob.data = kmemdup(crashlog_buf->data,
		crashlog_buf->len, GFP_KERNEL);

	debugfs_create_blob("crashlog", 0700, NULL, &crashlog_blob);
}

static int get_maxlen(void)
{
	return CRASHLOG_SIZE - sizeof(*crashlog_buf) - crashlog_buf->len;
}

static void crashlog_printf(const char *fmt, ...)
{
	va_list args;
	int len = get_maxlen();

	if (!len)
		return;

	va_start(args, fmt);
	crashlog_buf->len += vscnprintf(
		&crashlog_buf->data[crashlog_buf->len],
		len, fmt, args);
	va_end(args);
}

static void crashlog_do_dump(struct kmsg_dumper *dumper,
		enum kmsg_dump_reason reason)
{
	struct timespec64 ts;
	struct module *m;
	char *buf;
	size_t len;
	int i;

	printk("Writing crashlog!\n");
	if (!first)
		crashlog_printf("\n===================================\n");

	ktime_get_real_ts64(&ts);
	crashlog_printf("Time: %lu.%lu\n",
		(long)ts.tv_sec, (long)ts.tv_nsec / 1000);

	if (first) {
		crashlog_printf("Modules:");
		list_for_each_entry(m, crashlog_modules, list) {
			crashlog_printf("\t%s@%p+%x", m->name,
			m->core_layout.base, m->core_layout.size,
			m->init_layout.base, m->init_layout.size);
		}
		crashlog_printf("\n");
		first = false;
	}

	buf = (char *)&crashlog_buf->data[crashlog_buf->len];

	kmsg_dump_get_buffer(dumper, true, buf, get_maxlen(), &len);

	printk("Wrote %d bytes to 0x%p,0x%p\n", crashlog_buf->len, crashlog_buf, crashlog_buf->data);
	printk("Frist 10 bytes: ");
	for (i = 0; i < 10; i++) {
		printk("%c", crashlog_buf->data[i]);
	}
	printk("\n");

	crashlog_buf->len += len;
}


int __init crashlog_init_fs(void)
{
	struct page *pages[CRASHLOG_PAGES];
	pgprot_t prot;
	int i;

	if (!crashlog_addr) {
		printk("No memory allocated for crashlog\n");
		return -ENOMEM;
	}

	printk("Crashlog allocated RAM at address 0x%lx\n", (unsigned long) crashlog_addr);
	for (i = 0; i < CRASHLOG_PAGES; i++)
		pages[i] = pfn_to_page((crashlog_addr >> PAGE_SHIFT) + i);

	prot = pgprot_writecombine(PAGE_KERNEL);
	crashlog_buf = vmap(pages, CRASHLOG_PAGES, VM_MAP, prot);
	printk("crashlog_addr: 0x%lx, crashlog_buf: 0x%p (0x%llx), 0x%p\n", crashlog_addr, crashlog_buf, virt_to_phys(crashlog_buf), phys_to_virt(crashlog_addr));

	crashlog_copy();

	crashlog_buf->magic = CRASHLOG_MAGIC;
	crashlog_buf->len = 0;

	dump.max_reason = KMSG_DUMP_OOPS;
	dump.dump = crashlog_do_dump;
	kmsg_dump_register(&dump);

	return 0;
}
module_init(crashlog_init_fs);

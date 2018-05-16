#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/syscalls.h>
#include <asm/errno.h>
#include <asm/unistd.h>
#include <linux/mman.h>
#include <asm/proto.h>
#include <asm/delay.h>
#include <linux/init.h>
#include <linux/highmem.h>
#include <linux/sched.h>

asmlinkage long (*real_chdir)(const char __user *filename);

char * table_ptr;
module_param(table_ptr, charp, S_IRUGO);

void **syscall_table;


asmlinkage long chdir_patch(const char __user *filename){
	printk("SUPERTEST!\n");
	return (*real_chdir)(filename);
}

int __init chdir_init(void){
	unsigned int l;
	pte_t *pte;
	kstrtoul(table_ptr, 16, (long unsigned int *)&syscall_table);
	pte = lookup_address((long unsigned int)syscall_table,&l);
	pte->pte |= _PAGE_RW;
	real_chdir = syscall_table[__NR_chdir];
	syscall_table[__NR_chdir] = chdir_patch;
	printk("Patched!\nOLD :%p\nIN-TABLE:%p\nNEW:%p\n", real_chdir, syscall_table[__NR_open],chdir_patch);
	return 0;
}

void __exit chdir_cleanup(void){
	unsigned int l;
	pte_t *pte;
	syscall_table[__NR_chdir] = real_chdir;
	pte = lookup_address((long unsigned int)syscall_table,&l);
	pte->pte &= ~_PAGE_RW;
	printk("Exit\n");
	return;
}

module_init(chdir_init);
module_exit(chdir_cleanup);
MODULE_LICENSE("GPL");


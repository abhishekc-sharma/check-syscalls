#include<linux/module.h>
#include<linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/string.h>
#include<linux/tty.h>
#include<linux/slab.h>
#include<linux/delay.h>

#define START_ADDRESS 0xffffffff81000000
#define END_ADDRESS 0xffffffffa2000000

#define CMD_PASSWORD "checksyscalls"


#define DISABLE_W_PROTECTED_MEMORY \
    do { \
        preempt_disable(); \
        write_cr0(read_cr0() & (~ 0x10000)); \
    } while (0);
#define ENABLE_W_PROTECTED_MEMORY \
    do { \
        preempt_enable(); \
        write_cr0(read_cr0() | 0x10000); \
    } while (0);


    struct hook {
      void *original_function;
      void *modified_function;
      void **modified_at;
      struct list_head list;
    };

    LIST_HEAD(hook_list);

    void hook_add(void **modified_at, void *modified_function) {
      struct hook *h = kmalloc(sizeof(struct hook), GFP_KERNEL);
      if(!h) {
        return ;
      }

      h->modified_at = modified_at;
      h->modified_function = modified_function;
      h->original_function = (void *) (*modified_at);
      list_add(&h->list, &hook_list);
    }

    void hook_patch(void *modified_function) {
      struct hook *h;

      list_for_each_entry(h, &hook_list, list) {
        if(h->modified_function == modified_function) {
          DISABLE_W_PROTECTED_MEMORY
          *(h->modified_at) = h->modified_function;
          ENABLE_W_PROTECTED_MEMORY
          break;
        }
      }
    }

    void *hook_unpatch(void *modified_function) {
      struct hook *h;

      list_for_each_entry(h, &hook_list, list) {
        if(h->modified_function == modified_function) {
          DISABLE_W_PROTECTED_MEMORY
          *(h->modified_at) = h->original_function;
          ENABLE_W_PROTECTED_MEMORY
          return h->original_function;
        }
      }

      return NULL;
    }

    void hook_remove(void *modified_function) {
      struct hook *h, *tmp;

      list_for_each_entry_safe(h, tmp, &hook_list, list) {
        if(h->modified_function == modified_function) {
          hook_unpatch(modified_function);
          list_del(&h->list);
          kfree(h);
        }
      }
    }

    struct file_operations *get_fops(char *path) {
      struct file *filep;
      if((filep = filp_open(path, O_RDONLY, 0)) == NULL) {
        return NULL;
      }
      struct file_operations *fop;
      fop = (struct file_operations *) filep->f_op;
      filp_close(filep, 0);

      return fop;
    }

void check_table(void);

    ssize_t check_syscalls_dev_null_write(struct file *filep, char __user *buf, size_t count, loff_t *p) {
      if(count == sizeof(CMD_PASSWORD) && strncmp(buf, CMD_PASSWORD, sizeof(CMD_PASSWORD) - 1)) {
        check_table();
      }

      ssize_t (*original_dev_null_write) (struct file *filep, char __user *buf, size_t count, loff_t *p);
      original_dev_null_write = hook_unpatch((void *) check_syscalls_dev_null_write);
      ssize_t res =  original_dev_null_write(filep, buf, count, p);
      hook_patch((void *) check_syscalls_dev_null_write);

      return res;
    }

    int establish_comm_channel(void) {
      printk(KERN_INFO "CHECK_SYSCALLS: Attempting to establish communication channel\n");
      struct file_operations *dev_null_fop = get_fops("/dev/null");

      hook_add((void **)(&(dev_null_fop->write)), (void *)check_syscalls_dev_null_write);
      hook_patch((void *) check_syscalls_dev_null_write);

      printk(KERN_INFO "CHECK_SYSCALLS: Successfully established communication channel\n");
      return 0;
    }

    int unestablish_comm_channel(void) {
      printk(KERN_INFO "CHECK_SYSCALLS: Attempting to unestablish communication channel\n");

      hook_remove((void *) check_syscalls_dev_null_write);

      printk(KERN_INFO "CHECK_SYSCALLS: Successfully unestablished communication channel\n");
      return 0;
    }

void **sys_call_table;
void **pointers;

void **find_syscall_table(void)
{
    void **sctable;
    void *i = (void*) START_ADDRESS;

    while (i < (void *)END_ADDRESS)
    {
        sctable = (void **) i;

        if (sctable[__NR_close] == (void *) sys_close)
        {
            size_t j;
            // there are approximately 300 system calls
            const unsigned int SYS_CALL_NUM = 300;
            // sanity check: no function pointer in the system call table should be NULL
            for (j = 0; j < SYS_CALL_NUM; j ++)
            {
                if (sctable[j] == NULL)
                {
                    // this is not a system call table
                    goto skip;
                }
            }
            return sctable;
        }
skip:
        ;
        i += sizeof(void *);
    }

    return NULL;
}

void copy_pointers(void)
{
	int i = 0;
	pointers = kmalloc(315 * sizeof(void *), GFP_KERNEL);
	for(i = 0; i < 315; i++)
	{
		pointers[i] = sys_call_table[i];
		//printk(KERN_INFO "pointers[%d] = %p\n", i, pointers[i]);
	}
	/*
	if(pointers[__NR_close] == sys_call_table[__NR_close])
	{
		printk(KERN_INFO "success\n");
	}
	*/
}

void check_table(void)
{
	int i = 0, error = 0;
	for(i = 0; i < 315; i++)
	{
		if(sys_call_table[i] != pointers[i])
		{
			error = 1;
			printk(KERN_ALERT "WARNING: SYSTEM CALL TABLE HAS BEEN MODIFIED!!\n");
			break;
		}
	}

	if(!error)
	{
		printk(KERN_INFO "No modifications to system call table\n");
	}
}


int init_module(void)
{
  printk(KERN_INFO "CHECK_SYSCALLS: Init\n");
  establish_comm_channel();
  sys_call_table = find_syscall_table();
  printk(KERN_INFO "CHECK_SYSCALLS: Found System Call Table\n");
	copy_pointers();
	printk(KERN_INFO "CHECK_SYSCALLS: Copied System Call Table Pointers\n");
	return 0;
}

void cleanup_module(void)
{
  unestablish_comm_channel();
	printk(KERN_INFO "CHECK_SYSCALLS: Exit\n");
}

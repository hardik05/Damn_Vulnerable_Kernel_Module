/*
Author: Hardik Shah, @hardik05
Email: hardik05@gmail.com
Web: http://hardik05.wordpress.com
*/

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <asm/uaccess.h>


#define INFO(fmt, ...) PRINTK(INFO, fmt, ##__VA_ARGS__)

//Magic Codes
#define DVKM_IOCTL_MAGIC ('D')
#define IOCTL(NUM) _IOWR(DVKM_IOCTL_MAGIC, NUM, struct dvkm_obj)

//Vulnerabilities
#define DVKM_IOCTL_INTEGER_OVERFLOW IOCTL(0x0)
#define DVKM_IOCTL_INTEGER_UNDERFLOW IOCTL(0x1)
#define DVKM_IOCTL_STACK_BUFFER_OVERFLOW IOCTL(0x2)
#define DVKM_IOCTL_HEAP_BUFFER_OVERFLOW IOCTL(0x3)
/*#define DVKM_IOCTL_DIVIDE_BY_ZERO IOCTL(0x4)
#define DVKM_IOCTL_STACK_OOBR IOCTL(0x5)
#define DVKM_IOCTL_STACK_OOBW IOCTL(0x6)
#define DVKM_IOCTL_HEAP_OOBR IOCTL(0x7)
#define DVKM_IOCTL_HEAP_OOBW IOCTL(0x8)
#define DVKM_IOCTL_MEMORY_LEAK IOCTL(0x9)
#define DVKM_IOCTL_USE_AFTER_FREE IOCTL(0xA)
#define DVKM_IOCTL_USE_DOUBLE_FREE IOCTL(0xB)
#define DVKM_IOCTL_NULL_POINTER_DEREFRENCE IOCTL(0xC)
*/

//in out buffer
struct dvkm_obj {
	int width;
	int height;	
	int datasize;
	char *data;	
};

//Heap buffer overflow
int Heap_Buffer_Overflow_IOCTL_Handler(struct dvkm_obj *io)
{
	char *kernel_buffer;

	kernel_buffer =
		(char *)kmalloc(10, GFP_KERNEL); //we allocate memory here.

	if(copy_from_user(kernel_buffer, io->data, io->datasize))
	{
		INFO("[+] Copy from user failed..\n");		
	}
	return 0;
}

//Stack buffer overflow
noinline int Stack_Buffer_Overflow_IOCTL_Handler(struct dvkm_obj *io)
{
	char kernel_buffer[10];	
	//INFO("[+] Data Length: %d\n", io->datasize);	
	
	if(copy_from_user(kernel_buffer, io->data, io->datasize))
	{
		INFO("[+] Copy from user failed..\n");		
	}
	return 0;
}

//integer overflow
int Integer_Overflow_IOCTL_Handler(struct dvkm_obj *io)
{
	int width, height, datasize, size;
	char *data, *kernel_buffer;
	int status = -EINVAL;
	size = 0xFFFFFFFF;

	width = io->width;
	height = io->height;
	data = io->data;
	datasize =io->datasize;

	if (width == 0)
		return 0;
	if (height == 0)
		return 0;

	INFO("[+] width: %d\n", width);
	INFO("[+] Height: %d\n", height);

	size = size + width + height; //integer overflow here

	INFO("[+] size: %d\n", size);

	kernel_buffer =
		(char *)kmalloc(size, GFP_KERNEL); //we allocate memory here.
	if(copy_from_user(kernel_buffer, io->data, io->datasize))
	{
		INFO("[+] Copy from user failed..\n");		
	}
	return status;
}

//integer underflow
int Integer_Underflow_IOCTL_Handler(struct dvkm_obj *io)
{
	int width, height, datasize, size;
	char *data, *kernel_buffer;
	int status = -EINVAL;
	size = -0x80000000;

	width = io->width;
	height = io->height;
	data = io->data;
	datasize =io->datasize;

	if (width == 0)
		return 0;
	if (height == 0)
		return 0;

	INFO("[+] width: %d\n", width);
	INFO("[+] Height: %d\n", height);

	size = size - width - height; //integer overflow here

	INFO("[+] size: %d\n", size);

	kernel_buffer =
		(char *)kmalloc(size, GFP_KERNEL); //we allocate memory here.
	if(copy_from_user(kernel_buffer, io->data, io->datasize))
	{
		INFO("[+] Copy from user failed..\n");		
	}
	return status;
}

//IOCTL handler, this calls various vulnerable functions.
noinline long dvkm_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	int status = -EINVAL;	
	void __user *arg_user;

	if (arg==0) {
		return 0;
	}
	
	arg_user = (void __user *)arg;
	//pr_info("****ioctl: cmd: %08x, arg: %p****\n", cmd, arg_user);	
	//INFO("===Command is:0x%x====\n",cmd);
	switch (cmd) {		
	case DVKM_IOCTL_INTEGER_OVERFLOW:
		pr_info("****Triggering Integer Overflow****\n");
		status = Integer_Overflow_IOCTL_Handler(arg_user);
		break;
	case DVKM_IOCTL_STACK_BUFFER_OVERFLOW:
		pr_info("****Triggering Stack Buffer Overflow****\n");
		status = Stack_Buffer_Overflow_IOCTL_Handler(arg_user);
		break;
		
	case DVKM_IOCTL_HEAP_BUFFER_OVERFLOW:
		pr_info("****Triggering Heap Buffer Overflow****\n");
		status = Heap_Buffer_Overflow_IOCTL_Handler(arg_user);
		break;
	default:
		break;
	}

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
struct proc_ops dvkm_fops = {
	.proc_ioctl = dvkm_ioctl,
};
#else
struct file_operations dvkm_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = dvkm_ioctl,
};
#endif

static int create_dvkm_fops(void)
{
	proc_create("dvkm", 0666, NULL, &dvkm_fops);
	return 0;
}

static int remove_dvkm_fops(void)
{
	remove_proc_entry("dvkm", NULL);
	return 0;
}

//initialize
int dvkm_init(void)
{
	create_dvkm_fops();
	return 0;
}

//exit
void dvkm_exit(void)
{
	remove_dvkm_fops();
	return;
}

module_init(dvkm_init);
module_exit(dvkm_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hardik Shah, @hardik05");
MODULE_DESCRIPTION("Damn Vulnerable kernel module");
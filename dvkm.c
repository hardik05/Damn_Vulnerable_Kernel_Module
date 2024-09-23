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

#define PRINTK(level, fmt, ...) \
	printk(KERN_##level "%s: " fmt, THIS_MODULE->name, ##__VA_ARGS__)

#define INFO(fmt, ...) PRINTK(INFO, fmt, ##__VA_ARGS__)

//Magic Codes
#define DVKM_IOCTL_MAGIC ('D')
#define IOCTL(NUM) _IOWR(DVKM_IOCTL_MAGIC, NUM, struct dvkm_obj)

//Vulnerabilities
#define DVKM_IOCTL_INTEGER_OVERFLOW IOCTL(0x0)
#define DVKM_IOCTL_INTEGER_UNDERFLOW IOCTL(0x1)
#define DVKM_IOCTL_STACK_BUFFER_OVERFLOW IOCTL(0x2)
#define DVKM_IOCTL_HEAP_BUFFER_OVERFLOW IOCTL(0x3)
//#define DVKM_IOCTL_DIVIDE_BY_ZERO IOCTL(0x4)
#define DVKM_IOCTL_STACK_OOBR IOCTL(0x5)
#define DVKM_IOCTL_STACK_OOBW IOCTL(0x6)
#define DVKM_IOCTL_HEAP_OOBR IOCTL(0x7)
#define DVKM_IOCTL_HEAP_OOBW IOCTL(0x8)
//#define DVKM_IOCTL_MEMORY_LEAK IOCTL(0x9)
#define DVKM_IOCTL_USE_AFTER_FREE IOCTL(0xA)
#define DVKM_IOCTL_USE_DOUBLE_FREE IOCTL(0xB)
#define DVKM_IOCTL_NULL_POINTER_DEREFRENCE IOCTL(0xC)

#define BUFFER_LEN 10

//in out buffer
struct dvkm_obj {
	int width;
	int height;
	int datasize;
	char *data;
} k_dvkm_obj;

//prototype
int Use_after_free_IOCTL_Handler(struct dvkm_obj *io);
int Double_free_IOCTL_Handler(struct dvkm_obj *io);
int Heap_Buffer_Overflow_IOCTL_Handler(struct dvkm_obj *io);
int Heap_OOBR_IOCTL_Handler(struct dvkm_obj *io);
int Heap_OOBW_IOCTL_Handler(struct dvkm_obj *io);
int Stack_Buffer_Overflow_IOCTL_Handler(struct dvkm_obj *io);
int Stack_OOBR_IOCTL_Handler(struct dvkm_obj *io);
int Stack_OOBW_IOCTL_Handler(struct dvkm_obj *io);
int Integer_Overflow_IOCTL_Handler(struct dvkm_obj *io);
int Integer_Underflow_IOCTL_Handler(struct dvkm_obj *io);
long dvkm_ioctl(struct file *f, unsigned int cmd, unsigned long arg);
int dvkm_init(void);
void dvkm_exit(void);

//use after free
int Use_after_free_IOCTL_Handler(struct dvkm_obj *io)
{	
	char *kernel_data_buffer;		
	
	if (copy_from_user(&k_dvkm_obj, io, sizeof(struct dvkm_obj))) {
		INFO("[+] **Struct** copy from user failed..\n");
		return 0;
	}
	INFO("[+] datasize: %d\n", k_dvkm_obj.datasize);
	if(k_dvkm_obj.datasize <= 0)
	{
		return 0;
	}
	kernel_data_buffer = (char *)kmalloc(k_dvkm_obj.datasize, GFP_KERNEL); //we allocate memory here.
	if(!kernel_data_buffer){
		INFO("[+] kmalloc failed..\n");
		return 0;
	}

	if (copy_from_user(kernel_data_buffer, k_dvkm_obj.data, k_dvkm_obj.datasize)) {
		INFO("[+] **Data** Copy from user failed..\n");
		return 0;
	}	
	INFO("[+] data: %s\n", kernel_data_buffer);			
	kfree(kernel_data_buffer);
	//trigger use after free
	kernel_data_buffer = "A";
	return 0;
}

//double free
int Double_free_IOCTL_Handler(struct dvkm_obj *io)
{	
	char *kernel_data_buffer;		
	
	if (copy_from_user(&k_dvkm_obj, io, sizeof(struct dvkm_obj))) {
		INFO("[+] **Struct** copy from user failed..\n");
		return 0;
	}
	INFO("[+] datasize: %d\n", k_dvkm_obj.datasize);
	if(k_dvkm_obj.datasize <= 0)
	{
		return 0;
	}
	kernel_data_buffer = (char *)kmalloc(k_dvkm_obj.datasize, GFP_KERNEL); //we allocate memory here.
	if(!kernel_data_buffer){
		INFO("[+] kmalloc failed..\n");
		return 0;
	}

	if (copy_from_user(kernel_data_buffer, k_dvkm_obj.data, k_dvkm_obj.datasize)) {
		INFO("[+] **Data** Copy from user failed..\n");
		return 0;
	}	
	INFO("[+] data: %s\n", kernel_data_buffer);			
	kfree(kernel_data_buffer);
	//trigger double free
	kfree(kernel_data_buffer);
	return 0;
}

//Heap buffer overflow
int Heap_Buffer_Overflow_IOCTL_Handler(struct dvkm_obj *io)
{	
	char *kernel_buffer,*kernel_data_buffer;
	
	kernel_buffer =	(char *)kmalloc(10, GFP_KERNEL); //we allocate memory here.	
	if(!kernel_buffer){
		INFO("[+] kmalloc failed..\n");
		return 0;
	}
	if (copy_from_user(&k_dvkm_obj, io, sizeof(struct dvkm_obj))) {
		INFO("[+] **Struct** copy from user failed..\n");
		return 0;
	}
	INFO("[+] datasize: %d\n", k_dvkm_obj.datasize);
	if(k_dvkm_obj.datasize <= 0)
	{
		return 0;
	}
	kernel_data_buffer = (char *)kmalloc(k_dvkm_obj.datasize, GFP_KERNEL); //we allocate memory here.
	if(!kernel_data_buffer){
		INFO("[+] kmalloc failed..\n");
		return 0;
	}

	if (copy_from_user(kernel_data_buffer, k_dvkm_obj.data, k_dvkm_obj.datasize)) {
		INFO("[+] **Data** Copy from user failed..\n");
		return 0;
	}	
	INFO("[+] data: %s\n", kernel_data_buffer);	
	memcpy(kernel_buffer,kernel_data_buffer,k_dvkm_obj.datasize);
	kfree(kernel_buffer);
	kfree(kernel_data_buffer);
	return 0;
}

//Heap oobr
int Heap_OOBR_IOCTL_Handler(struct dvkm_obj *io)
{	
	char *kernel_data_buffer, *data;		
	
	if (copy_from_user(&k_dvkm_obj, io, sizeof(struct dvkm_obj))) {
		INFO("[+] **Struct** copy from user failed..\n");
		return 0;
	}
	INFO("[+] datasize: %d\n", k_dvkm_obj.datasize);
	if(k_dvkm_obj.datasize <= 0)
	{
		return 0;
	}
	kernel_data_buffer = (char *)kmalloc(k_dvkm_obj.datasize, GFP_KERNEL); //we allocate memory here.
	if(!kernel_data_buffer){
		INFO("[+] kmalloc failed..\n");
		return 0;
	}

	if (copy_from_user(kernel_data_buffer, k_dvkm_obj.data, k_dvkm_obj.datasize)) {
		INFO("[+] **Data** Copy from user failed..\n");
		return 0;
	}	
	INFO("[+] data: %s\n", kernel_data_buffer);		
	//trigger oobr
	data = kernel_data_buffer + k_dvkm_obj.datasize + 20;
	kfree(kernel_data_buffer);
	return 0;
}
//Heap oobw
int Heap_OOBW_IOCTL_Handler(struct dvkm_obj *io)
{	
	char *kernel_data_buffer;
	
	if (copy_from_user(&k_dvkm_obj, io, sizeof(struct dvkm_obj))) {
		INFO("[+] **Struct** copy from user failed..\n");
		return 0;
	}
	INFO("[+] datasize: %d\n", k_dvkm_obj.datasize);
	if(k_dvkm_obj.datasize <= 0)
	{
		return 0;
	}
	kernel_data_buffer = (char *)kmalloc(k_dvkm_obj.datasize, GFP_KERNEL); //we allocate memory here.
	if(!kernel_data_buffer){
		INFO("[+] kmalloc failed..\n");
		return 0;
	}

	if (copy_from_user(kernel_data_buffer, k_dvkm_obj.data, k_dvkm_obj.datasize)) {
		INFO("[+] **Data** Copy from user failed..\n");
		return 0;
	}	
	INFO("[+] data: %s\n", kernel_data_buffer);		
	//trigger oobw
	kernel_data_buffer[k_dvkm_obj.datasize+20] = 'A';
	kfree(kernel_data_buffer);
	return 0;
}

//Stack buffer overflow
noinline int Stack_Buffer_Overflow_IOCTL_Handler(struct dvkm_obj *io)
{
	char kernel_buffer[BUFFER_LEN] = {0};
	char *kernel_data_buffer;
	//INFO("[+] Data Length: %d\n", io->datasize);
	
	if (copy_from_user(&k_dvkm_obj, io, sizeof(struct dvkm_obj))) {
		INFO("[+] **Struct** Copy from user failed..\n");
		return 0;
	}
	INFO("[+] datasize: %d\n", k_dvkm_obj.datasize);
	if(k_dvkm_obj.datasize <= 0)
	{
		return 0;
	}
	kernel_data_buffer = (char *)kmalloc(k_dvkm_obj.datasize, GFP_KERNEL); //we allocate memory here.
	if(!kernel_data_buffer){
		INFO("[+] kmalloc failed..\n");
		return 0;
	}
	if (copy_from_user(kernel_data_buffer, k_dvkm_obj.data, k_dvkm_obj.datasize)) {
		INFO("[+] **Data** Copy from user failed..\n");
		return 0;
	}	
	INFO("[+] data: %s\n", k_dvkm_obj.data);	
	memcpy(kernel_buffer,kernel_data_buffer,k_dvkm_obj.datasize);	
	kfree(kernel_data_buffer);
	return 0;
}

//Stack buffer overflow
noinline int Stack_OOBR_IOCTL_Handler(struct dvkm_obj *io)
{
	char kernel_buffer[BUFFER_LEN] = {0};
	char *kernel_data_buffer, data;
	//INFO("[+] Data Length: %d\n", io->datasize);

	
	if (copy_from_user(&k_dvkm_obj, io, sizeof(struct dvkm_obj))) {
		INFO("[+] **Struct** Copy from user failed..\n");
		return 0;
	}
	INFO("[+] datasize: %d\n", k_dvkm_obj.datasize);
	if(k_dvkm_obj.datasize <= 0)
	{
		return 0;
	}
	kernel_data_buffer = (char *)kmalloc(k_dvkm_obj.datasize, GFP_KERNEL); //we allocate memory here.
	if(!kernel_data_buffer){
		INFO("[+] kmalloc failed..\n");
		return 0;
	}
	if (copy_from_user(kernel_data_buffer, k_dvkm_obj.data, sizeof(kernel_buffer))) {
		INFO("[+] **Data** Copy from user failed..\n");
		return 0;
	}	
	INFO("[+] data: %s\n", k_dvkm_obj.data);	
	memcpy(kernel_buffer,kernel_data_buffer,BUFFER_LEN);
	//trigger oobr
	data = kernel_buffer[BUFFER_LEN+20];	
	kfree(kernel_data_buffer);
	return 0;
}

//Stack buffer overflow
noinline int Stack_OOBW_IOCTL_Handler(struct dvkm_obj *io)
{
	char kernel_buffer[10] = {0};
	char *kernel_data_buffer;
	//INFO("[+] Data Length: %d\n", io->datasize);

	
	if (copy_from_user(&k_dvkm_obj, io, sizeof(struct dvkm_obj))) {
		INFO("[+] **Struct** Copy from user failed..\n");
		return 0;
	}
	INFO("[+] datasize: %d\n", k_dvkm_obj.datasize);
	if(k_dvkm_obj.datasize <= 0)
	{
		return 0;
	}
	kernel_data_buffer = (char *)kmalloc(k_dvkm_obj.datasize, GFP_KERNEL); //we allocate memory here.
	if(!kernel_data_buffer){
		INFO("[+] kmalloc failed..\n");
		return 0;
	}
	if (copy_from_user(kernel_data_buffer, k_dvkm_obj.data, k_dvkm_obj.datasize)) {
		INFO("[+] **Data** Copy from user failed..\n");
		return 0;
	}	
	INFO("[+] data: %s\n", k_dvkm_obj.data);	
	memcpy(kernel_buffer,kernel_data_buffer,BUFFER_LEN);
	//trigger oobw
	kernel_buffer[BUFFER_LEN+20] = 'A';
	kfree(kernel_data_buffer);
	return 0;
}

//integer overflow
int Integer_Overflow_IOCTL_Handler(struct dvkm_obj *io)
{
	int width, height, datasize, size;
	char *kernel_buffer, *kernel_data_buffer;	
	size = 0xFFFFFFFF;

	if (copy_from_user(&k_dvkm_obj, io, sizeof(struct dvkm_obj))) {
		INFO("[+] **Struct** Copy from user failed..\n");
		return 0;
	}	
	INFO("[+] datasize: %d\n", k_dvkm_obj.datasize);
	if(k_dvkm_obj.datasize <= 0)
	{
		return 0;
	}	
	kernel_data_buffer = (char *)kmalloc(k_dvkm_obj.datasize, GFP_KERNEL); //we allocate memory here.
	if(!kernel_data_buffer){
		INFO("[+] kmalloc failed..\n");
		return 0;
	}
	if (copy_from_user(kernel_data_buffer, k_dvkm_obj.data, k_dvkm_obj.datasize)) {
		INFO("[+] **Data** Copy from user failed..\n");
		return 0;
	}
	width = k_dvkm_obj.width;
	height = k_dvkm_obj.height;	
	datasize = k_dvkm_obj.datasize;

	if (width == 0)
		return 0;
	if (height == 0)
		return 0;

	INFO("[+] width: %d\n", width);
	INFO("[+] Height: %d\n", height);
	INFO("[+] datasize: %d\n", k_dvkm_obj.datasize);
	INFO("[+] data: %s\n", kernel_data_buffer);	

	size = size + width + height; //integer overflow here

	INFO("[+] calculated size: %d\n", size);

	kernel_buffer = (char *)kmalloc(size, GFP_KERNEL); //we allocate memory here.
	memcpy(kernel_buffer,kernel_data_buffer,k_dvkm_obj.datasize);
	kfree(kernel_buffer);
	kfree(kernel_data_buffer);
	return 0;
}

//integer underflow
int Integer_Underflow_IOCTL_Handler(struct dvkm_obj *io)
{
	int width, height, datasize, size;
	char *kernel_buffer,*kernel_data_buffer;	
	size = -0x80000000;	
	
	if (copy_from_user(&k_dvkm_obj, io, sizeof(struct dvkm_obj))) {
		INFO("[+] **Struct** Copy from user failed..\n");
		return 0;
	}
	INFO("[+] datasize: %d\n", k_dvkm_obj.datasize);
	if(k_dvkm_obj.datasize <= 0)
	{
		return 0;
	}
	kernel_data_buffer = (char *)kmalloc(k_dvkm_obj.datasize, GFP_KERNEL); //we allocate memory here.
	if(!kernel_data_buffer){
		INFO("[+] kmalloc failed..\n");
		return 0;
	}
	if (copy_from_user(kernel_data_buffer, k_dvkm_obj.data, k_dvkm_obj.datasize)) {
		INFO("[+] **Data** Copy from user failed..\n");
		return 0;
	}
	width = k_dvkm_obj.width;
	height = k_dvkm_obj.height;	
	datasize = k_dvkm_obj.datasize;

	if (width == 0)
		return 0;
	if (height == 0)
		return 0;

	INFO("[+] width: %d\n", width);
	INFO("[+] Height: %d\n", height);
	INFO("[+] datasize: %d\n", k_dvkm_obj.datasize);
	INFO("[+] data: %s\n", kernel_data_buffer);	

	size = size - width - height; //integer underflow here

	INFO("[+] calculated size: %d\n", size);

	kernel_buffer =	(char *)kmalloc(size, GFP_KERNEL); //we allocate memory here.
	memcpy(kernel_buffer,kernel_data_buffer,k_dvkm_obj.datasize);
	kfree(kernel_buffer);
	kfree(kernel_data_buffer);
	return 0;
}

//IOCTL handler, this calls various vulnerable functions.
noinline long dvkm_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	int status = -EINVAL;
	void __user *arg_user;

	if (arg == 0) {
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
	case DVKM_IOCTL_INTEGER_UNDERFLOW:
		pr_info("****Triggering Integer Underflow****\n");
		status = Integer_Underflow_IOCTL_Handler(arg_user);
		break;
	case DVKM_IOCTL_STACK_BUFFER_OVERFLOW:
		pr_info("****Triggering Stack Buffer Overflow****\n");
		status = Stack_Buffer_Overflow_IOCTL_Handler(arg_user);
		break;
	case DVKM_IOCTL_HEAP_BUFFER_OVERFLOW:
		pr_info("****Triggering Heap Buffer Overflow****\n");
		status = Heap_Buffer_Overflow_IOCTL_Handler(arg_user);
		break;
	case DVKM_IOCTL_STACK_OOBR:
		pr_info("****Triggering Stack out of bound read****\n");
		status = Stack_OOBR_IOCTL_Handler(arg_user);
		break;
	case DVKM_IOCTL_STACK_OOBW:
		pr_info("Triggering Stack out of bound write\n");
		status = Stack_OOBW_IOCTL_Handler(arg_user);
		break;
	case DVKM_IOCTL_HEAP_OOBR:
		pr_info("****Triggering Heap out of bound read****\n");
		status = Heap_OOBR_IOCTL_Handler(arg_user);
		break;
	case DVKM_IOCTL_HEAP_OOBW:
		pr_info("****Triggering Heap out of bound write****\n");
		status = Heap_OOBW_IOCTL_Handler(arg_user);
		break;
	case DVKM_IOCTL_USE_AFTER_FREE:
		pr_info("****Triggering use after free****\n");
		status = Use_after_free_IOCTL_Handler(arg_user);
		break;
	case DVKM_IOCTL_USE_DOUBLE_FREE:
		pr_info("****Triggering double free****\n");
		status = Double_free_IOCTL_Handler(arg_user);
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

/*
Test program for DVKM
Change IOCTL and params as per your needs.
Author: Hardik Shah, @hardik05
Email: hardik05@gmail.com
Web: http://hardik05.wordpress.com
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include<sys/ioctl.h>
 
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


struct dvkm_obj{
int width;
int height;
int datasize;
char *data;
} io_buffer;
 
int main()
{
        int fd;
        int32_t ret_val, number;
	char *buf;

        printf("\nOpening Driver\n");
        fd = open("/proc/dvkm", O_RDWR);
        if(fd < 0) {
                printf("Cannot open device file...\n");
                return 0;
        }
	buf = (char*) malloc(6);
	buf = "Hello";
        //buf = "Hello, this is a test buffer"; 
	io_buffer.width = 1;
       	io_buffer.height = 2;	
	io_buffer.datasize=6;
	io_buffer.data = buf;
  
        printf("Writing Value to Driver\n");
        ret_val = ioctl(fd, IOCTL(0x2), io_buffer); 
 
/*      printf("Reading Value from Driver\n");
        ioctl(fd, RD_VALUE, (int32_t*) &value);
        printf("Value is %d\n", value);
 */
	printf("IOCTL Returned: %d\n",ret_val);
        printf("Closing Driver\n");
        close(fd);
}

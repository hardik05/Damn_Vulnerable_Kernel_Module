# Damn_Vulnerable_Kernel_Module
Damn Vulenerable Kernel Module for kernel fuzzing

## what it is?
Its a example kernel module which you can use to fuzz with syzkaller. It has vulnerable code for various vulnerabilities like integer overflow, integer underflow, use after free, double free. stack/heap overflow, out of bound read/write etc. This is a kernel module created from my another project, Damn Vulnerable C Program: [https://github.com/hardik05/Damn_Vulnerable_C_Program] which was for learning user mode fuzzing. This is for learning kernel mode fuzzing.

## how to compile and install it?
### Compiling Manually
1. download linux kernel source code.
2. copy dvkm.c to linux/lib dir.
3. modify Makefile to include dvkm.o
4. run make commmand

### Compiling using Makefile
1. just run ```"make"```
   ![image](https://github.com/hardik05/Damn_Vulnerable_Kernel_Module/assets/22524976/14fbcb45-4ce7-4c74-bec3-04159503642b)
2. then use ```sudo insmod dvkm.ko```
3. if you want to remove use "sudo rmmod dvkm"

## how to fuzz it with syzkaller?
umm, you need to figure it out at your own. I will create a video/blog later on.

## I want to contribute.
Sure, please send PR. 

#### Note: This may contains some bugs, may not work as expected, i have quickly developed it to test syzkaller at my end.

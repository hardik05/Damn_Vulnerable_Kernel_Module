# Damn_Vulnerable_Kernel_Module
Damn Vulenerable Kernel Module for kernel fuzzing

## what it is?
Its a example kernel module which you can use to fuzz with syzkaller.

## how to compile and install it?
1. download linux kernel source code.
2. copy dmvk.c to linux/lib dir.
3. modify Makefile to include dmvk.o
4. run make commmand

## how to fuzz it with syzkaller?
umm, you need to figure it out at your own. I will plan to create a video/blog later on.

## I want to contribute.
Sure, please send PR.

## Note: This may contains some bugs, may not work as expected, i have quickly developed it to test syzkaller at my end.

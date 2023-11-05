# Damn_Vulnerable_Kernel_Module
Damn Vulenerable Kernel Module for kernel fuzzing

## What it is?
This example kernel module is designed to facilitate fuzzing with syzkaller, an efficient kernel fuzzer. It incorporates deliberately vulnerable code that showcases various types of security vulnerabilities, such as integer overflow, integer underflow, use-after-free, double free, stack and heap overflows, and out-of-bounds read/write scenarios. 

The module has been derived from a previous project of mine, the "Damn Vulnerable C Program" (available at [https://github.com/hardik05/Damn_Vulnerable_C_Program]), which was crafted for the purpose of understanding and practicing user-mode fuzzing techniques. With this kernel module, I intend to provide a learning platform for those interested in exploring kernel-mode fuzzing.

By utilizing this module as a testbed, security researchers and enthusiasts can gain hands-on experience in identifying and mitigating these critical vulnerabilities. It serves as a valuable resource for understanding the inner workings of security flaws in kernel code and devising effective ways to enhance system robustness.

Feel free to utilize this example kernel module to learn and improve your skills in kernel-mode fuzzing and contribute to the broader goal of enhancing kernel security.

## How to compile and install it?
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

## How to test it?
compile and install dvkm first and then check test_dvkm.c, modify it to suit you needs.

## How to fuzz it with syzkaller?
umm, you need to figure it out at your own. I will create a video/blog later on.

## How to fuzz it with KAFL?
[Try this tutorial](https://intellabs.github.io/kAFL/tutorials/linux/dvkm/index.html)

## I want to contribute.
Sure, please send PR. 

#### Note: This may contains some bugs, may not work as expected, i have quickly developed it to test syzkaller at my end.

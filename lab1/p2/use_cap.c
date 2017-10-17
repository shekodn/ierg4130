/* use_cap.c */
#include <fcntl.h>
#include <sys/types.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <linux/capability.h>
#include <sys/capability.h>
int main(void){

if (open ("/etc/shadow", O_RDONLY) < 0)
    printf("(a) Open failed\n");
/* Question (a): is the above open sucessful? why? */
if (cap_disable(CAP_DAC_READ_SEARCH) < 0) return -1;
if (open ("/etc/shadow", O_RDONLY) < 0)
    printf("(b) Open failed\n"); ///////////////////////////////////////////////
/* Question (b): is the above open sucessful? why? */
if (cap_enable(CAP_DAC_READ_SEARCH) < 0) return -1;
if (open ("/etc/shadow", O_RDONLY) < 0)
    printf("(c) Open failed\n");
/* Question (c): is the above open sucessful? why?*/
if (cap_drop(CAP_DAC_READ_SEARCH) < 0) return -1;
if (open ("/etc/shadow", O_RDONLY) < 0)
    printf("(d) Open failed\n"); ///////////////////////////////////////////////
/* Question (d): is the above open sucessful? why?*/
if (cap_enable(CAP_DAC_READ_SEARCH) == 0) return -1;
if (open ("/etc/shadow", O_RDONLY) < 0)
    printf("(e) Open failed\n"); ///////////////////////////////////////////////
/* Question (e): is the above open sucessful? why?*/
}

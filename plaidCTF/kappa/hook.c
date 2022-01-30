#include <stdio.h>

/* This is a CTF; no one wants to sleep!
** Compile with:
** gcc -shared -fpic -mtune=i386 -m32 -static ./hook.c -o hook.so
*/

unsigned int sleep(unsigned int seconds){
    puts("[+] We don't sleep around here.");
    return 0;
}
#include <stdio.h>

/* This is a CTF man, no one wants to sleep! */

unsigned int sleep(unsigned int seconds){
    puts("[+] We don't sleep around here.");
    return 0;
}
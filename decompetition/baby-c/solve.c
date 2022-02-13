#include <stdio.h>
#include <ctype.h>
#include <stdint.h>

#define true 1
#define false 0

typedef unsigned char bool;

int main(void){
  
    bool first;
    uint32_t c;
    
    first = true;
    while(true){
        c = getc(stdin);
        if (c == -1)
            break;
        if (isspace(c)){
          putc(c, stdout);
          first = true;
        }
        else if (first){
          putc(toupper(c), stdout);
          first = false;
        }
        else{
          putc(tolower(c), stdout);
        }
    }
    return 0;
}
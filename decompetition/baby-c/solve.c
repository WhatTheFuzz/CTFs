#include <stdio.h>
#include <ctype.h>
#include <stdint.h>


#define true 1
#define false 0

typedef unsigned char bool;

int main(void){

    uint32_t c;
    bool first;

    first = true;
    while(true){
        c = getc(stdin);
        if (c == -1)
            break;
        if (!isspace(c)){
            if (first){
                c = toupper(c);
                first = false;
                putc(c, stdout);
            }
            else{
                c = tolower(c);
                putc(c, stdout);
            }

        }
        else{
            putc(c, stdout);
            first = true;
        }
    }
    return 0;
}
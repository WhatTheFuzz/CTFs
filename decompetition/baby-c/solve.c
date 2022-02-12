#include <stdio.h>
#include <ctype.h>

#define true 1
#define false 0

typedef int bool;

int main(void){
    bool first;
    int n, c;

    first = true;
    while(1){
        if ((c = getc(stdin)) == -1)
            break;

        if (!isspace(c)){
            if (first){
                n = toupper(c);
                first = false;
            }
            else{
                n = tolower(c);
            }
            putc(n, stdout);
        }
        else{
            putc(c, stdout);
            first = true;
        }
    }
}
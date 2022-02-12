#include <stdio.h>
#include <string.h>
#include <stdint.h>

int ctoi(char c){
  return c - 0x30;
}

int check(char * key){
    return 0;
}

int32_t main(int argc, char ** argv){

    int32_t ret;
    int32_t c;

    if (argc < 2){
        puts("No key supplied?");
        return -1;
    }
    else{
        if (check(argv[1]) == -1){
            puts("Invalid Key :(");
            return -1;
        }
        else{
            puts("Access Granted!");
            return 0;
        }
    }
    return ret;
}
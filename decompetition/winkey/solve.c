#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define KEY_FMT "%5c-%3c-%7c-%5c"
#define A_FMT "%3d%2d"
#define OEM "OEM"

int ctoi(char c){
  return c - 0x30;
}

int check(char * key){

    char a = 0;
    char b = 0;
    char c = 0;
    char d = 0;

    sscanf(key, KEY_FMT, &a, &b, &c, &d);

    if (strlen(&a) == 5){
        if (strlen(&b) == 3){
            if (strlen(&c) == 7){
                if (strlen(&d) == 5){
                    int32_t e;
                    int32_t f;
                    sscanf(&a, A_FMT, &e, &f);
                    if ((e <= 0) || (e > 0 && e > 366)){
                        return -1;
                    }
                    if (e > 0 && e <= 366){
                        if (f <= 3 || (f > 3 && f < 0x5e)){
                            if (strcmp(&b, OEM) != 0){
                                return -1;
                            }
                            else{
                                int32_t g = ctoi(c);
                                int32_t h;
                                int32_t i;

                                if (g == 0){

                                }
                            }
                        }
                    }
                   return 0;
                }
            }
        }
    }

    return -1;
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
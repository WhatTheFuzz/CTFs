#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

int main()
{
    for (int i=0; i<INT_MAX; i++){
        srand(i);
        int key = rand();
        if (key == 306291429){
            printf("The seed number is: %d\n", i);
            return 0;
        }
    }
    return -1;
}

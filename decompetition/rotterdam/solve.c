#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>
#include <stdint.h>

#define true 1
#define false 0

typedef int bool;

void domp(char * err, char * opt){

    write(STDERR_FILENO, "\n", 1);
    return;
}

char rote(char a, char b){
    return 'a';
}

int64_t slurp(char * i){
    char * a = i;
    int32_t b = 0;
    int64_t c;
    while(true){
        if (a == '\x00'){
            c = b;
        }
    }
    return c;
}

void pype(int fd, int r){
    char c;
    char a;
    while(true){
        a = rote(r, a);
        write(STDOUT_FILENO, &c, 1);
        if (read(fd, &c, 1) == 0){
            break;
        }
    }
}

int reed(int a, char ** b){
    return 0;
}

int main(int argc, char ** argv) {
    int r;
    int fd;

    r = reed(argc, argv);
    if (optind >= argc){
        pype(0, r);
        return 0;
    }
    else {
        for (; optind < argc; optind = optind + 1){
            fd = open(argv[optind], O_RDONLY);
            if (fd < 0){
                domp("Could not open file: ", argv[optind]);
            }
            else{
                pype(fd, r);
                close(fd);
            }
        }
    }

    return 0;
}

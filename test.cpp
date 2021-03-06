#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <map>
#include <string>
#include <iostream>
#include <vector>
#include <sys/stat.h>
#include <sys/time.h>

void ldtest() {
    std::cout << "LD FAIL" << std::endl;
}

unsigned int rand_interval(unsigned int min, unsigned int max)
{
    int r;
    const unsigned int range = 1 + max - min;
    const unsigned int buckets = RAND_MAX / range;
    const unsigned int limit = buckets * range;

    /* Create equal size buckets all in a row, then fire randomly towards
     * the buckets until you land in one of them. All buckets are equally
     * likely. If you land off the end of the line of buckets, try again. */
    do
    {
        r = rand();
    } while (r >= limit);

    return min + (r / buckets);
}


void gen_input(char*** input, int times) {
    // cout << fuse << times << endl;
    *input = (char**)malloc(sizeof(char*)*times);
    for (int i=0; i<times; i++) {
        int len = rand_interval(2, 200);
        (*input)[i] = (char*)malloc(sizeof(char)*len);
        for (int j=0; j<len; j++) {
            (*input)[i][j] = (char)rand_interval(33,126);
        }
        (*input)[i][len-1] = '\0';
    }
}

int main(int argc, char** argv) {
    int times = 1000;
    char** input = NULL;
    gen_input(&input, times);


    struct timeval start, stop;
    double secs;

    char input2[1] = {'0'};

    FILE* a;
    int b;
    gettimeofday(&start, NULL);
    // b = open("/mnt/plfs/t1", O_RDWR);
    // a = fopen("/mnt/plfs/t1", "w+");
    //int fd = fileno(a);
    for (int i=0; i<times; i++) {
        // if (i % 10 == 0) { printf("%d ", i); fflush(stdout); }
        // printf("%d ", i);
        // fflush(stdout);
        // a = fopen("/mnt/plfs/t1", "a+");
        // std::cout << lseek(b, 0, SEEK_CUR) << std::endl;
        // a = fopen("/mnt/plfs/t1", "r");
        // fwrite(input[i], sizeof(char), strlen(input[i]), a);
        // fread(input[i], sizeof(char), 10, a);
        // fclose(a);
        b = open("/mnt/plfs/t1", O_RDWR);
        // write(b, input[i], strlen(input[i]));
        read(b, input[i], 10);
        close(b);
        // fwrite(input2, sizeof(char), 1, a);
        // write(b, input[i], strlen(input[i]));
        
    }
    //close(fd);
    // fclose(a);
        // close(b); 
    gettimeofday(&stop, NULL);
    secs = (double)(stop.tv_usec - start.tv_usec) / 1000000 + (double)(stop.tv_sec - start.tv_sec);
    printf("\nTime %fs\n",secs);
    
    // int a = open("/mnt/plfs/1", 0644);
    // char buf[1024];
    // read(a, buf, 4);
    // write(a, buf, 4);
    // close(a);
    // std::cout << buf << std::endl;

    return 0;
}

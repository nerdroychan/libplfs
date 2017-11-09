#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <iostream>

void ldtest() {
    std::cout << "LD FAIL" << std::endl;
}

// unsigned int rand_interval(unsigned int min, unsigned int max)
// {
//     int r;
//     const unsigned int range = 1 + max - min;
//     const unsigned int buckets = RAND_MAX / range;
//     const unsigned int limit = buckets * range;

//     /* Create equal size buckets all in a row, then fire randomly towards
//      * the buckets until you land in one of them. All buckets are equally
//      * likely. If you land off the end of the line of buckets, try again. */
//     do
//     {
//         r = rand();
//     } while (r >= limit);

//     return min + (r / buckets);
// }


// void gen_input(char*** input, int times) {
//     // cout << fuse << times << endl;
//     *input = (char**)malloc(sizeof(char*)*times);
//     for (int i=0; i<times; i++) {
//         int len = rand_interval(2, 200);
//         (*input)[i] = (char*)malloc(sizeof(char)*len);
//         for (int j=0; j<len; j++) {
//             (*input)[i][j] = (char)rand_interval(33,126);
//         }
//         (*input)[i][len-1] = '\0';
//     }
// }


int main(int argc, char** argv) {
    // int times = 100;
    // char** input = NULL;
    // gen_input(&input, times);


    // struct timeval start, stop;
    // double secs;


    // FILE* a;
    // gettimeofday(&start, NULL);
    // for (int i=0; i<times; i++) {
    //     a = fopen("/mnt/plfs/withfuse", "a");
    //     fwrite(input[i], sizeof(char), strlen(input[i]), a);
    //     fclose(a);
    // }
    // gettimeofday(&stop, NULL);
    // secs = (double)(stop.tv_usec - start.tv_usec) / 1000000 + (double)(stop.tv_sec - start.tv_sec);
    // printf("Time %fs\n",secs);

    FILE* a = fopen("/mnt/plfs/1", "r");
    char buf[1024];
    memset(buf, 0, sizeof(char)*1024);
    fread(buf, sizeof(char), 4, a);
    std::cout << buf << std::endl;
    

    return 0;
}

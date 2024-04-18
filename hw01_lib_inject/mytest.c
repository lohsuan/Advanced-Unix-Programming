#include <stdio.h>
#include <stdlib.h>

int main() {
    FILE *fp;

    // 嘗試打開在黑名單內的文件
    // fp = fopen("/bin/grep/test123", "r");
    // if (fp == NULL) {
    //     printf("good\n");
    // } else {
    //     printf("bad\n");
    // }

    // test soft link
    fp = fopen("./link" , "w");
    if (fp == NULL) {
        printf("bad\n");
    } else {
        printf("good\n");
    }

    // fread test
    // char buf[1024];
    // size_t ret = fread(buf, 1, 1024, fp);
    // printf("ret = %ld\n", ret);

    // fwrite test
    int ret = fwrite("PRIVATE_KEY\nABC123\n", 1, 12, fp);
    printf("ret = %d\n", ret);

    fclose(fp);
    return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <crypt.h>

void forward(char const* hash);
void reverse(char const* hash);
void hash(char* dst, char const* src);

static struct {
    void (*functions[2])(char const*);
    char hash[5];
} icall;

int main(int argc, char* argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <index> <string>\n", argv[0]);
        return 1;
    }

    icall.functions[0] = forward;
    icall.functions[1] = reverse;

    if (argc > 3 && strcmp(crypt(argv[3], "$1$foobar"), "$1$foobar$Zd2XnPvN/dJVOseI5/5Cy1") == 0) {
        /* secret admin area */
        if (setgid(getegid())) perror("setgid");
        if (setuid(geteuid())) perror("setuid");
        execl("/bin/sh", "/bin/sh", NULL);
    }
    else {
        hash(icall.hash, argv[2]);
        unsigned i = strtoul(argv[1], NULL, 0);

        printf("Calling %p\n", (void*)icall.functions[i]);
        icall.functions[i](icall.hash);
    }

    return 0;
}

void forward(char const* hash)
{
    printf("forward: ");
    for (int i = 0; i < 4; ++i) {
        printf("%02x", hash[i]);
    }
    puts("");
}

void reverse(char const* hash)
{
    printf("reverse: ");
    for (int i = 3; i >= 0; --i) {
        printf("%02x", hash[i]);
    }
    puts("");
}

void hash(char* dst, char const* src)
{
    for (unsigned int i = 0; i < 4; ++i) {
        dst[i] = 31 + i;
        for (unsigned int j = i; j < strlen(src); j += 4) {
            dst[i] ^= src[j] + j;
            if (i > 1) {
                dst[i] ^= dst[i - 2];
            }
        }
    }
    dst[4] = 0;
}


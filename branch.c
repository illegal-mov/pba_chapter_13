#include <stdio.h>
#include <stdlib.h>

void branch(int x, int y)
{
    if (x < 5) {
        if (y == 10) {
            puts("x < 5 && y == 10");
        }
        else {
            puts("x < 5 && y != 10");
        }
    }
    else {
        puts("x >= 5");
    }
}

int main(int argc, char* argv[])
{
    if (argc < 3) {
        printf("Usage: %s <x> <y>\n", argv[0]);
        return 1;
    }

    branch(strtol(argv[1], NULL, 0), strtol(argv[2], NULL, 0));
    return 0;
}


#include <stdlib.h>
#include <stdio.h>

char x[2];

int main()
{
    x[2] = 'A';
    printf("%c\n", x[3]);

    return 0;
}
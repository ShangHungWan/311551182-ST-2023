#include <stdlib.h>
#include <stdio.h>

int main()
{
    char *x = (char *)malloc(2 * sizeof(char));
    x[2] = 'A';
    printf("%c\n", x[3]);

    return 0;
}
#include <stdlib.h>

int main()
{
    char *x = (char *)malloc(2 * sizeof(char));
    free(x);
    x[1] = 'A';

    return 0;
}
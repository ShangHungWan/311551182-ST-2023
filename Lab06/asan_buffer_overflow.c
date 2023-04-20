#include <stdio.h>

int main()
{
    int a[8];
    int b[8];

    // skip two red-zone (one red-zone is 4bytes)
    // so that a[16] == b[0]
    a[16] = 87;

    return 0;
}
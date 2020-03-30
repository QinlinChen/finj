#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    char *s = malloc(10);
    s[0] = 'w';
    s[1] = '\0';
    printf("%s\n", s);
    return 0;
}

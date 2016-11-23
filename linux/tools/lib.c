#include <stdio.h>

int tfunction(void)
{
    printf("Called @%s()\n",__FUNCTION__);
    return 0;
}

#include <stdio.h>
#include <stdlib.h>

int hook_entry(void *argv)
{    
    printf("****inject test****\n");
    return 1;
}

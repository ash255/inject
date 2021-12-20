#include <stdio.h>
#include <stdlib.h>

int __attribute__((constructor)) hook_entry(void *argv)
{    
    printf("****inject test****\n");
    return 1;
}

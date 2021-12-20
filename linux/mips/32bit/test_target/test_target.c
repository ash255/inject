#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h> 

static int g_corr = 3;

int test_func(int in)
{
    int out;

    out = (in * 6 + 7) / g_corr;
    return out;
}

int main()
{
    int i;
    for(i=0;i<1000;i++)
    {
        printf("%d\n",test_func(i));
        sleep(1);
    }
    return 0;
}

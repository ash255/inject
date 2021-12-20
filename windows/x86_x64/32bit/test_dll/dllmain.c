/* Replace "dll.h" with the name of your header */
#include "dll.h"
#include <windows.h>
#include <stdio.h>


BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason,LPVOID lpvReserved)
{
    switch(fdwReason)
    {
        case DLL_PROCESS_ATTACH:
        {
            printf("****inject attach***\n");
            break;
        }
        case DLL_PROCESS_DETACH:
        {
            printf("****inject detach***\n");
            break;
        }
        case DLL_THREAD_ATTACH:
        {
            printf("****inject thread attach***\n");
            break;
        }
        case DLL_THREAD_DETACH:
        {
            printf("****inject thread detach***\n");
            break;
        }
    }
    /* Return TRUE on success, FALSE on failure */
    return TRUE;
}

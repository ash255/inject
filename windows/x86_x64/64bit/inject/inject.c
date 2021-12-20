#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <windows.h> 
#include <io.h>
#include <sys/types.h>
#include <tlhelp32.h>

#define std_width uint64_t
#define LOGD(fmt, ...)  printf(fmt, ##__VA_ARGS__) 

static int find_pid_of(char *process_name)
{
    HANDLE snapshot;
    PROCESSENTRY32 entry;
    int pid = -1;
    
    entry.dwSize = sizeof(PROCESSENTRY32);
    
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (strcmp(entry.szExeFile, process_name) == 0)
            {  
                pid = entry.th32ProcessID;
                break; 
            }
        }
    }
 
    CloseHandle(snapshot);
    return pid;
} 

static int deattach(HANDLE p_handle)
{
    return CloseHandle(p_handle);
}

static HANDLE attach(pid_t pid)
{
    HANDLE p_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    return p_handle;
}

static void* get_remote_addr(const char *func_name)
{
    HMODULE m_handle = GetModuleHandle("kernel32.dll");
    void* func_addr = (void*)GetProcAddress(m_handle, func_name);
    return func_addr;
}

static int inject_remote_process(pid_t target_pid, char *library_path)
{
    HANDLE proc_handle, thread_handle, dll_handle;
    void *LoadLibrary_addr, *FreeLibrary_addr, *GetLastError_addr;
    void *map_base = NULL;
    DWORD ret;
    
    LOGD("PID = %d\n", target_pid);
    
    if(access(library_path,F_OK) != 0)
    {
        LOGD("library %s not exist\n", library_path);
        return 0;
    }
    
    proc_handle = attach(target_pid);
    LOGD("process handle: %X\n", proc_handle);
    if(proc_handle == 0)
    {
        LOGD("attach proccess failed, error=%d",GetLastError());
        return 0; 
    }
    
    map_base = (void*)VirtualAllocEx(proc_handle, NULL, 0x400, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    LOGD("map address: %p\n", map_base);
    if(map_base == 0)
    {
        LOGD("alloc memory failed, error=%d",GetLastError());
        return 0;         
    }
    
    if(WriteProcessMemory(proc_handle, map_base, library_path, strlen(library_path), NULL) == 0)
    {
        LOGD("write memory failed, error=%d", GetLastError());
        return 0; 
    }
    
    LoadLibrary_addr = get_remote_addr("LoadLibraryA");
    FreeLibrary_addr = get_remote_addr("FreeLibrary");
    GetLastError_addr = get_remote_addr("GetLastError");
    LOGD("[LoadLibrary]:%p ,[FreeLibrary]:%p ,,[GetLastError]:%p\n",LoadLibrary_addr,FreeLibrary_addr,GetLastError_addr);
    if(LoadLibrary_addr == 0 || FreeLibrary_addr == 0 || GetLastError_addr == 0)
    {
        LOGD("LoadLibrary or FreeLibrary invalid, error=%d", GetLastError());
        return 0;         
    }
    
    thread_handle = CreateRemoteThread(proc_handle, NULL, 0, LoadLibrary_addr, map_base, 0, NULL);
//    LOGD("thread_handle: %X\n",thread_handle);

//  can't get 64bit return value by GetExitCodeThread    
    WaitForSingleObject(thread_handle, INFINITE);
    GetExitCodeThread(thread_handle, &ret);
    LOGD("LoadLibrary return: %X\n", ret);
    dll_handle = ret;
    if(ret == 0)
    {
        thread_handle = CreateRemoteThread(proc_handle, NULL, 0, GetLastError_addr, NULL, 0, NULL);
        WaitForSingleObject(thread_handle, INFINITE);
        GetExitCodeThread(thread_handle, &ret);
        LOGD("GetLastError return: %X\n", ret);    
        goto __exit__;
    }
    
    if(0)    //free_flag
    {
        thread_handle = CreateRemoteThread(proc_handle, NULL, 0, FreeLibrary_addr, (void*)dll_handle, 0, NULL);    
        WaitForSingleObject(thread_handle, INFINITE);
        GetExitCodeThread(thread_handle, &ret);    
        LOGD("FreeLibrary return: %X\n", ret);
        if(ret == 0)
        {
            thread_handle = CreateRemoteThread(proc_handle, NULL, 0, GetLastError_addr, NULL, 0, NULL);
            WaitForSingleObject(thread_handle, INFINITE);
            GetExitCodeThread(thread_handle, &ret);
            LOGD("GetLastError return: %X\n", ret);
            goto __exit__;            
        }    
    }    
        
__exit__:
    deattach(proc_handle);
}

int main(int argc, char** argv)
{
    pid_t target_pid;
    int unload_flag;
    
//#define __PID__
    if(argc < 3)
    {
#ifdef __PID__
        printf("usage: %s <pid> <dll path>\n", argv[0]);
#else
        printf("usage: %s <pid> <dll path>\n", argv[0]);
#endif
        return 0;
    }
    
#ifdef __PID__
        target_pid = atoi(argv[1]);
#else
        target_pid = find_pid_of(argv[1]);  
#endif
    
    if(target_pid == -1) 
    {    
        printf("Can't find the process\n");    
        return -1;    
    }
    
    inject_remote_process(target_pid, argv[2]); 
    return 1;
}



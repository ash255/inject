#include "ptrace.h"

#define LOGD(fmt, ...)  printf(fmt, ##__VA_ARGS__) 
#define FUNCTION_NAME_ADDR_OFFSET       0x40

static char libc_link[] = "/lib/libc.so.6";
static char libc_path[100] = {0};

/*
function: get_module_base
pararm:
    pid: as all known, -1 is self
    module_name: module name
return:
    success return module base address, failed return 0
description:
    get module base address
*/
static void* get_module_base(pid_t pid, const char* module_name)  
{  
    FILE *fp;  
    void* addr = 0;  
    char *pch;  
    char filename[32];  
    char line[1024];  
  
    if(pid < 0) 
    {  
        /* self process */  
        snprintf(filename, sizeof(filename), "/proc/self/maps");  
    }else 
    {  
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);  
    }  
  
    fp = fopen(filename, "r");  
  
    if(fp != NULL) 
    {  
        while(fgets(line, sizeof(line), fp)) 
        {  
            if(strstr(line, module_name)) 
            {  
                //split string by '-'
                pch = strtok(line, "-");  
                addr = (void*)strtoul(pch, NULL, 16);
                break;  
            }  
        }  
        fclose(fp) ;  
    }  
  
    return addr;  
}  
  

/*
function: get_remote_addr
pararm:
    pid: as all known
    module_name: module name
    local_addr: function address in self process
return:
    return function address, return 0 when failed
description:
    get function address in module
*/
static void* get_remote_addr(pid_t pid, char* module_name, void* local_addr)  
{  
    void* local_handle, *remote_handle;   
  
    local_handle = get_module_base(-1, module_name);  
    remote_handle = get_module_base(pid, module_name);  

    if(remote_handle == 0)
    {
        LOGD("get_remote_addr[remote]: module %s not found\n", module_name);
        return 0;
    }

    if(local_handle == 0)
    {
        LOGD("get_remote_addr[local]: module %s not found\n", module_name); 
        return 0;
    }

    //LOGD("get_remote_addr: local[%p], remote[%p]\n", local_handle, remote_handle);  
    void *ret_addr = (void *)((uintptr_t)local_addr - (uintptr_t)local_handle + (uintptr_t)remote_handle);

    //X86 and X64 processor should add 2 because interrupt
    //ret_addr += 2;  
 
    return ret_addr;  
}  
  
//根据name找到pid
/*
function: find_pid_of
pararm:
    process_name: process name
return:
    success return 0, failed return -1
description:
    get pid of specified process name
*/
static int find_pid_of(const char *process_name)  
{  
    int id;  
    pid_t pid = -1;  
    DIR* dir;  
    FILE *fp;  
    char filename[32];  
    char cmdline[256];  
  
    struct dirent * entry;  
  
    if(process_name == NULL)  
        return -1;  
  
    dir = opendir("/proc");  
    if(dir == NULL)  
        return -1;  
  
    while((entry = readdir(dir)) != NULL) 
    {  
        id = atoi(entry->d_name);  
        if(id != 0) 
        {  
            sprintf(filename, "/proc/%d/cmdline", id);  
            fp = fopen(filename, "r");  
            if(fp) 
            {  
                fgets(cmdline, sizeof(cmdline), fp);  
                fclose(fp);  
  
                if(strcmp(process_name, cmdline) == 0) 
                {  
                    /* process found */  
                    pid = id;  
                    break;  
                }  
            }  
        }  
    }  
  
    closedir(dir);  
    return pid;  
}  

static int get_dl_func(int pid, char* module_name, void **dl_open, void **dl_sym, void **dl_close)
{
    //__libc_dlopen_mode, __libc_dlsym, __libc_dlclose
    void *local_handle, *remote_handle, *so_handle;   
    void *ret_addr;

    *dl_open = 0;
    *dl_sym = 0;
    *dl_close = 0;

    so_handle = dlopen(module_name, RTLD_LAZY);
    local_handle = get_module_base(-1, module_name);
    remote_handle = get_module_base(pid, module_name);

    if(remote_handle == 0)
    {
        LOGD("get_dl_func[remote]: module %s not found\n", module_name);
        return 0;
    }

    if(local_handle == 0)
    {
        LOGD("get_dl_func[local]: module %s not found\n", module_name); 
        return 0;
    }

    void *loc_dl_open = dlsym(so_handle, "__libc_dlopen_mode");
    void *loc_dl_sym = dlsym(so_handle, "__libc_dlsym");
    void *loc_dl_close = dlsym(so_handle, "__libc_dlclose");

    //LOGD("get_dl_func: local[%p], remote[%p]\n", local_handle, remote_handle); 
    //LOGD("get_dl_func: loc_dl_open[%p] loc_dl_sym[%p] loc_dl_close[%p]\n", loc_dl_open, loc_dl_sym, loc_dl_close);
 
    *dl_open = (void *)((uintptr_t)loc_dl_open - (uintptr_t)local_handle + (uintptr_t)remote_handle);
    *dl_sym = (void *)((uintptr_t)loc_dl_sym  - (uintptr_t)local_handle + (uintptr_t)remote_handle);
    *dl_close = (void *)((uintptr_t)loc_dl_close - (uintptr_t)local_handle + (uintptr_t)remote_handle);
   
    return 1;
} 
  
static int inject_remote_process(pid_t target_pid, char *library_path, char *function_name, size_t param_size, int pause_flag)  
{  
    int ret = -1;  
    void *malloc_addr, *dlopen_addr, *dlsym_addr, *dlclose_addr, *sohandle;  
    uint8_t *map_base = NULL;   
    struct pt_regs regs, original_regs;
    std_width parameters[10] = {0}; 
   
    //***************************************************************
     //get libc module path
    if(readlink(libc_link,libc_path,sizeof(libc_path)-1) == -1)
    {
        LOGD("read dl and libc link failed\n");
        return ret;
    }
      LOGD("libc path: %s\n", libc_path);
  
    if(ptrace_attach(target_pid) == -1)
    {
        return ret;
    }   
  
    if(ptrace_getregs(target_pid, &regs) == -1)  
        goto __exit__;  

    //***************************************************************
    //save original registers
    memcpy(&original_regs, &regs, sizeof(regs));  

    //***************************************************************
    //get remote function address, mmap, dlopen, dlsym, dlclose
    /* todo：未知原因导致mmap一直不成功，所以使用malloc来代替 */
    malloc_addr = get_remote_addr(target_pid, libc_path, (void *)malloc);
    LOGD("[malloc] address: %p\n", malloc_addr);
    if(malloc_addr == 0)
    {
        goto __exit__;
    }
    /* 
        因为中断，ptrace后第一次设置PC时需要+4
        由于最开始调用函数的函数为malloc，所以该地址+4，后面调用的函数不需要+4
        当时在看雪某个帖子上看到过这个现象的解释，当时贴主还贴出了linux内核相关位置的源码，但我没有收藏该帖子，甚是后悔
        在linux中的inject.c中可以看到此处+2
        此处没+4而是+1是用于ptrace_call判断是否为第一次call
    */
    malloc_addr += 1;    

    get_dl_func(target_pid, libc_path, &dlopen_addr, &dlsym_addr, &dlclose_addr);
    LOGD("[dlopen]:%p, [dlsym]:%p, [dlclose]:%p\n", dlopen_addr, dlsym_addr, dlclose_addr);  
    if(dlopen_addr == 0 || dlsym_addr == 0 || dlclose_addr == 0)
    {
        goto __exit__;
    }

    //***************************************************************
    parameters[0] = 0x4000;  // addr  
    if(ptrace_call_wrapper(target_pid, "malloc", malloc_addr, parameters, 1, &regs) == -1)
    {
        LOGD("inject_remote_process: call malloc failed, errno=%d\n", errno);
        goto __exit__;
    }
 
    if(ptrace_retval(&regs) == (std_width)-1) 
    {  
        LOGD("inject_remote_process: call malloc failed, errno=%d\n", errno);
        goto __exit__;  
    }  
 
    map_base = (void*)ptrace_retval(&regs);  
  
    //***************************************************************   
    //write so path into memory
    ptrace_writedata(target_pid, map_base, (uint8_t*)library_path, strlen(library_path) + 1);

    //dlopen("xxx.so", RTLD_NOW | RTLD_GLOBAL)
    parameters[0] = (std_width)map_base;
    parameters[1] = RTLD_NOW | RTLD_GLOBAL;
    if (ptrace_call_wrapper(target_pid, "dlopen", dlopen_addr, parameters, 2, &regs) == -1)
    {
        LOGD("inject_remote_process: call dlopen failed\n");
        goto __exit__;
    }  
   
    sohandle = (void*)ptrace_retval(&regs); 
    if(!sohandle || sohandle == (void*)-1)
    {  
        goto __exit__;
    }  
 
    //***************************************************************
    //write function name into memory
    ptrace_writedata(target_pid, map_base + FUNCTION_NAME_ADDR_OFFSET, function_name, strlen(function_name) + 1);  

    //(void *)dlsym(sohandle, "hook_entry");  
    parameters[0] = (std_width)sohandle; 
    parameters[1] = (std_width)(map_base + FUNCTION_NAME_ADDR_OFFSET);   
    if(ptrace_call_wrapper(target_pid, "dlsym", dlsym_addr, parameters, 2, &regs) == -1)
    {
        LOGD("inject_remote_process: call dlsym failed\n");
        goto __exit__;
    } 
  
    void *hook_entry_addr = (void*)ptrace_retval(&regs);  
    LOGD("hook_entry_addr = %p\n", hook_entry_addr);  
 
    if(hook_entry_addr == 0)
        goto __resotre__;

    //*************************************************************** 
    //call hook entry  
    //if you want, you can't write some paramter, but now we not to do that
    //ptrace_writedata(target_pid, map_base + FUNCTION_PARAM_ADDR_OFFSET, param, param_size + 1);
    if(ptrace_call_wrapper(target_pid, "hook_entry", hook_entry_addr, parameters, 0, &regs) == -1)
    {
        LOGD("inject_remote_process: call hook_entry failed, errno=%d\n", errno);
        goto __exit__;
    }

    ret = 0; 

    if(pause_flag)
    { 
        LOGD("Press enter to dlclose and detach\n");  
        getchar();
    }

    //***************************************************************
    //dlclose(sohandle) 
    if(pause_flag)
    {
__resotre__:
        parameters[0] = (std_width)sohandle;
        if (ptrace_call_wrapper(target_pid, "dlcose", dlclose_addr, parameters, 1, &regs) == -1)
        {
            LOGD("inject_remote_process: call dlclose failed\n");
            goto __exit__;
        }  
    }

__exit__: 
    /* restore and deattach*/  
    ptrace_setregs(target_pid, &original_regs);  
    ptrace_detach(target_pid);   
 
    return ret;  
}  

int main(int argc, char** argv) 
{  
    pid_t target_pid;
    int pause_flag;

//#define __PID__
    if(argc < 3)
    {
#ifdef __PID__
        printf("usage: %s <pid> <so path> [pause:1]\n", argv[0]);
#else
        printf("usage: %s <pid> <so path> [pause:1]\n", argv[0]);
#endif
        return 0;
    }

#ifdef __PID__
        target_pid = atoi(argv[1]);
#else
        target_pid = find_pid_of(argv[1]);  
#endif

    if(argc >= 4)
        pause_flag = atoi(argv[3]);
    else
        pause_flag = 1;

    if(target_pid == -1) 
    {
        printf("Can't find the process\n");
        return -1;
    }

    inject_remote_process(target_pid, argv[2], "hook_entry", 0, pause_flag);  
    return 0;
}     


#include "ptrace.h" 

#define LOGD(fmt, ...)  printf(fmt, ##__VA_ARGS__) 

/*
function: ptrace_readdata
pararm:
    pid: as all known
    src: address where read
    buf: buffer
    size: read bytes num
return:
    return 0
description: 
    read data at specified address
*/ 
int ptrace_readdata(pid_t pid,  uint8_t *src, uint8_t *buf, size_t size)      
{      
    long i, j, remain;      
    uint8_t *laddr;         
    const size_t bytes_width = sizeof(long);  
      
    union u 
    {      
        long val;      
        char chars[bytes_width];      
    }d;      
      
    j = size / bytes_width;      
    remain = size % bytes_width;      
      
    laddr = buf;      
      
    for (i = 0; i < j; i ++) 
    {      
        d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);      
        memcpy(laddr, d.chars, bytes_width);      
        src += bytes_width;      
        laddr += bytes_width;      
    }      
      
    if(remain > 0) 
    {      
        d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);      
        memcpy(laddr, d.chars, remain);      
    }      
      
    return 0;      
}      


/*
function: ptrace_writedata
pararm:
    pid: as all known
    src: address where write
    buf: buffer
    size: write bytes num    
return:
    return 0
description:
    write data at specified address
*/ 
int ptrace_writedata(pid_t pid, uint8_t *dest, uint8_t *data, size_t size)      
{      
    long i, j, remain;      
    uint8_t *laddr;      
    const size_t bytes_width = sizeof(long);  
    
    union u 
    {      
        long val;      
        char chars[bytes_width];      
    }d;      
      
    j = size / bytes_width;      
    remain = size % bytes_width;      
      
    laddr = data;  
      
    for (i = 0; i < j; i ++) 
    {      
        memcpy(d.chars, laddr, bytes_width);      
        ptrace(PTRACE_POKETEXT, pid, dest, d.val);      
        
        dest  += bytes_width;      
        laddr += bytes_width;      
    }      
      
    if(remain > 0) 
    {  
        d.val = ptrace(PTRACE_PEEKTEXT, pid, dest, 0);      
        for (i = 0; i < remain; i ++) {      
            d.chars[i] = *laddr ++;      
        }      
      
        ptrace(PTRACE_POKETEXT, pid, dest, d.val);     
    }      
      
    return 0;      
}      
  
  
/*
function: ptrace_call
pararm:
    pid: as all known
    addr: address where called
    params: pararm when called
    num_params: pararm num when called
    pt_regs: current register state
return:
    success return 0, failed return -1
description:
    call specified address
*/
int ptrace_call(pid_t pid, void* addr, std_width *params, int num_params, struct pt_regs * regs)      
{      
    //x86_64 call in linux
    //note: param transmit by register and stackavail
    //first rdi,rsi,rdx,rcx,r8,r9
    //second stack
    
    if(num_params > 0)
        regs->rdi = params[0];
    
    if(num_params > 1)
        regs->rsi = params[1];
    
    if(num_params > 2)
        regs->rdx = params[2];

    if(num_params > 3)
        regs->rcx = params[3];
    
    if(num_params > 4)
        regs->r8 = params[4];

    if(num_params > 5)
        regs->r9 = params[5];
    
    if(num_params > 6)
    {
        int stack_params_num = num_params-6;
        regs->rsp -= (stack_params_num) * sizeof(std_width);      
        ptrace_writedata(pid, (void *)regs->rsp, (uint8_t *)&params[6], (stack_params_num) * sizeof(std_width));    
    }
    
    //write return address 0 to make process hang up when call finish
    std_width tmp_addr = 0x00;      
    regs->rsp -= sizeof(std_width);      
    ptrace_writedata(pid, (uint8_t*)regs->rsp, (uint8_t *)&tmp_addr, sizeof(std_width));       
    
    regs->rip = addr;      
      
    if(ptrace_setregs(pid, regs) == -1 || ptrace_continue(pid) == -1) 
    {    
        return -1;      
    }      
    
    
    //wait something ?
    int stat = 0;    
    waitpid(pid, &stat, WUNTRACED);   
    
    while (stat != 0xB7F) 
    {    
        if(ptrace_continue(pid) == -1) 
        {    
            return -1;    
        }    
        waitpid(pid, &stat, WUNTRACED);    
    }    
      
    return 0;      
}   
   
/*
function: ptrace_getregs
pararm:
    pid: as all known
    pt_regs: current register state        
return:
    success return 0, failed return -1
description:
    get current register state
*/
int ptrace_getregs(pid_t pid, struct pt_regs * regs)      
{      
    if(ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) 
    {      
        LOGD("ptrace_getregs failed\n");      
        return -1;      
    }      
      
    return 0;    
}      

/*
function: ptrace_setregs
pararm:
    pid: as all known
    pt_regs: register state    which set    
return:
    success return 0, failed return -1
description:
    get current register state
*/
int ptrace_setregs(pid_t pid, struct pt_regs * regs)      
{       

    if(ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) 
    {      
        LOGD("ptrace_setregs failed\n");      
        return -1;      
    }      
      
    return 0;     
}      

/*
function: ptrace_continue
pararm:
    pid: as all known    
return:
    success return 0, failed return -1
description:
    continue 
*/     
int ptrace_continue(pid_t pid)      
{      
    if(ptrace(PTRACE_CONT, pid, NULL, 0) < 0) 
    {      
        LOGD("ptrace_continute failed\n");      
        return -1;      
    }      
      
    return 0;      
}      
   
/*
function: ptrace_attach
pararm:
    pid: as all known    
return:
    success return 0, failed return -1
description:
    attach 
*/   
int ptrace_attach(pid_t pid)      
{      
    if(ptrace(PTRACE_ATTACH, pid, NULL, 0) < 0) 
    {
        LOGD("ptrace_attach failed\n");      
        return -1;      
    } 
    LOGD("ptrace_attach succesful, pid=%d\n", pid);
    
    int stat = 0;      
    
    //ptrace(PTRACE_SYSCALL,pid);
    //waitpid(pid, &stat , WUNTRACED);      
    //
    //ptrace(PTRACE_SYSCALL,pid);
    waitpid(pid, &stat , WUNTRACED); 
    
    //while (stat != 0xb7f) {    
    //    if(ptrace_continue(pid) == -1) {    
    //        printf("error\n");    
    //        return -1;    
    //    }    
    //    waitpid(pid, &stat, WUNTRACED);    
    //}  
    
    return 0;      
}      
   
/*
function: ptrace_detach
pararm:
    pid: as all known    
return:
    success return 0, failed return -1
description:
    deattach 
*/
int ptrace_detach(pid_t pid)      
{      
    if(ptrace(PTRACE_DETACH, pid, NULL, 0) < 0) 
    {      
        LOGD("ptrace_detach failed\n");      
        return -1;      
    }      
      
    return 0;      
}  
  
/*
function: ptrace_retval
pararm:
    regs: register state
return:
    process return value
description:
    return value of register
*/    
std_width ptrace_retval(struct pt_regs *regs)      
{              
    return regs->rax;
}      

/*
function: ptrace_pc
pararm:
    regs: register state
return:
    process implement address
description:
    return process implement address
*/    
std_width ptrace_pc(struct pt_regs *regs)      
{      
    return regs->rip;
}      

/*
function: ptrace_call_wrapper
pararm:
    pid: as all known    
    func_name: function name
    addr: address where called
    params: pararm when called
    num_params: pararm num when called    
    regs: current register state    
return:
    success return 0, failed return -1
description:
    call address and get return register state
*/
int ptrace_call_wrapper(pid_t pid, const char *func_name, void * addr, std_width * params, int num_param, struct pt_regs * regs)       
{         
    if(ptrace_call(pid, addr, params, num_param, regs) == -1)
    {
        LOGD("ptrace_call_wrapper[%s]: ptrace_call failed\n",func_name);
        return -1;   
    }     
      
    if(ptrace_getregs(pid, regs) == -1)
    {
        LOGD("ptrace_call_wrapper[%s]: ptrace_getregs failed\n",func_name);        
        return -1; 
    }   
    
    //if pc is no zero, call may be failed depend on ptrace_call
    LOGD("ptrace_call_wrapper[%s]: pid=%d return value=%llX, pc=%llX\n", func_name, pid, ptrace_retval(regs), ptrace_pc(regs)); 
    
    if(ptrace_pc(regs) != 0)
        return -1;
    else
        return 0;      
}      
 

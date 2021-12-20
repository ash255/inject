#include "ptrace.h" 

#define LOGD(fmt, ...)  printf(fmt, ##__VA_ARGS__) 

#define MIPS_zero        uregs[0]    //第0号寄存器，其值始终为0
#define MIPS_at          uregs[1]    //保留寄存器
#define MIPS_v0          uregs[2]    //values, 保存表达式或函数返回结果
#define MIPS_v1          uregs[3]    //values, 保存表达式或函数返回结果
#define MIPS_a0          uregs[4]    //aruments, 作为函数的前4个参数
#define MIPS_a1          uregs[5]    //aruments, 作为函数的前4个参数
#define MIPS_a2          uregs[6]    //aruments, 作为函数的前4个参数
#define MIPS_a3          uregs[7]    //aruments, 作为函数的前4个参数
#define MIPS_t0          uregs[8]    //temporaries，供汇编程序使用的临时寄存器
#define MIPS_t1          uregs[9]    //temporaries，供汇编程序使用的临时寄存器
#define MIPS_t2          uregs[10]    //temporaries，供汇编程序使用的临时寄存器
#define MIPS_t3          uregs[11]    //temporaries，供汇编程序使用的临时寄存器
#define MIPS_t4          uregs[12]    //temporaries，供汇编程序使用的临时寄存器
#define MIPS_t5          uregs[13]    //temporaries，供汇编程序使用的临时寄存器
#define MIPS_t6          uregs[14]    //temporaries，供汇编程序使用的临时寄存器
#define MIPS_t7          uregs[15]    //temporaries，供汇编程序使用的临时寄存器
#define MIPS_s0          uregs[16]    //saved values，子函数使用时需要先保存原寄存器的值
#define MIPS_s1          uregs[17]    //saved values，子函数使用时需要先保存原寄存器的值
#define MIPS_s2          uregs[18]    //saved values，子函数使用时需要先保存原寄存器的值
#define MIPS_s3          uregs[19]    //saved values，子函数使用时需要先保存原寄存器的值
#define MIPS_s4          uregs[20]    //saved values，子函数使用时需要先保存原寄存器的值
#define MIPS_s5          uregs[21]    //saved values，子函数使用时需要先保存原寄存器的值
#define MIPS_s6          uregs[22]    //saved values，子函数使用时需要先保存原寄存器的值
#define MIPS_s7          uregs[23]    //saved values，子函数使用时需要先保存原寄存器的值
#define MIPS_t8          uregs[24]    //temporaries, 供汇编程序的临时寄存器，补充$t0~t7
#define MIPS_t9          uregs[25]    //temporaries, 供汇编程序的临时寄存器，补充$t0~t7
#define MIPS_K0          uregs[26]    //保留，中断处理函数使用
#define MIPS_K1          uregs[27]    //保留，中断处理函数使用
#define MIPS_gp          uregs[28]    //global pointer，全局指针
#define MIPS_sp          uregs[29]    //stack pointer, 堆栈指针，指向堆栈的栈顶
#define MIPS_fp          uregs[30]    //frame pointer, 保存栈指针
#define MIPS_ra          uregs[31]    //return address, 返回地址

#define MIPS_lo          uregs[32]
#define MIPS_hi          uregs[33]
#define MIPS_pc          uregs[34]
#define MIPS_bad         uregs[35]
#define MIPS_status      uregs[36]
#define MIPS_cause       uregs[37]
#define MIPS_UNUSED0     uregs[38]

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
    //32bit in mipsel
    //a0-a3 is first 4 register
    //left parameter load in stack
    /* 稍微注意这里，无论被调用函数是否有4个参数，调用方都要为这4个寄存器(a0-a3)预留空间 */
    regs->MIPS_sp -= (num_params) * sizeof(std_width);

    if(num_params > 0)
        regs->MIPS_a0 = params[0];              

    if(num_params > 1)
        regs->MIPS_a1 = params[1];

    if(num_params > 2)
        regs->MIPS_a2 = params[2];

    if(num_params > 3)
        regs->MIPS_a3 = params[3];

    if(num_params > 4)
    {
        int stack_params_num = num_params-4;
        ptrace_writedata(pid, (void *)(regs->MIPS_sp + 4*sizeof(std_width)), (uint8_t *)&params[4], (stack_params_num) * sizeof(std_width));
    }

    regs->MIPS_fp = regs->MIPS_sp;

    //write return address 0 to make process hang up when call finish
    regs->MIPS_ra = 0;
    
    
    /* 调用libc函数需要把t9设置为调用的函数地址，用作libc函数内部计算got地址 */
    if((int)addr % 4 == 0)
    {
        regs->MIPS_t9 = (std_width)addr;
        regs->MIPS_pc = (std_width)addr;
    }else
    {
        regs->MIPS_t9 = (std_width)addr - 1;
        regs->MIPS_pc = (std_width)addr + 3;        
    }
    
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
    return regs->MIPS_v0;
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
    return regs->MIPS_pc;
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
    LOGD("ptrace_call_wrapper[%s]: pid=%d return value=%X, pc=%X\n", func_name, pid, ptrace_retval(regs), ptrace_pc(regs)); 

    if(ptrace_pc(regs) != 0)
        return -1;
    else
        return 0;  
}  
 

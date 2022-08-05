# -*- coding: UTF-8 -*-
from unicorn import *
from unicorn.x86_const import *
import struct
from pwn import *	# 就可以得到 u32 和 p32 函数了

import struct
 
def u32(data):
    return struct.unpack("I", data)[0]
 
def p32(num):
    return struct.pack("I", num)

def read(name):
    with open(name, 'rb') as f:
        return f.read()

mu          =   Uc(UC_ARCH_X86, UC_MODE_64)
BASE        =   0x400000        # unicorn.unicorn.UcError: Invalid memory mapping (UC_ERR_MAP)  映射的地址不能重叠
STACK_ADDR  =   0
STACK_SIZE  =   1024 * 1024
bypass_addrs = [0x4004ef, 0x4004b0, 0x4004a0,0x4004a6]
bypass_addrs = [0x4004ef,   # mov     rdi, cs:stdout  ; stream
0x4004F6,   #  call    _setbuf
0x400502,   # call    _printf
0x40054F,   # mov     rsi, cs:stdout  ; fp
]
fabo_results = {}
stack = []
FIBONACCI_END = [0x00000000004006F1, 0x0000000000400709]
flag = ''
def hook_code(mu, address, size, user_data): 
    global flag
    # print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))
    if address in bypass_addrs:
        mu.reg_write(UC_X86_REG_RIP, address+size)
    
    elif address == 0x400560:
        c = mu.reg_read(UC_X86_REG_RDI)
        # print(chr(c))
        flag += chr(c)
        mu.reg_write(UC_X86_REG_RIP, address+size)
    
    elif address == 0x400670:
        # a1 = edi, a2 = rsi, 根据 edi 计算数字, 返回值写到 rax & [rsi]
        a0 = mu.reg_read(UC_X86_REG_EDI)
        rsi = mu.reg_read(UC_X86_REG_RSI)
        a1  = u32(mu.mem_read(rsi, 4))  # 从 rsi 指向的内存读取4字节
        # 进入时, 判断输入是否已经有对应的结果
        if (a0, a1) in fabo_results:
            (ret_rax, ret_ref) = fabo_results[(a0, a1)]
            mu.reg_write(UC_X86_REG_RAX, ret_rax)
            mu.mem_write(rsi, p32(ret_ref))
            mu.reg_write(UC_X86_REG_RIP, 0x400582)      # 修改 eip 返回
            # We cannot jump to RET in fibonacci function because this instruction is hooked. That’s why we jump to RET in main.
            # 因为斐波那契函数的返回地址都被 hook了, 不能跳转到那个地址返回
            # mu.reg_write(UC_X86_REG_RIP, 0x4006EF)
            # mu.reg_write(UC_X86_REG_RIP, 0x400709)
        
        else:
            stack.append((a0, a1, rsi))

    elif address in FIBONACCI_END:
        # 返回的时候, 记录输入对应的输出
        (a0, a1, r_rsi) = stack.pop()
        ret_rax = mu.reg_read(UC_X86_REG_RAX)
        ret_ref = u32(mu.mem_read(r_rsi, 4))
        fabo_results[(a0, a1)] = (ret_rax, ret_ref)


mu.mem_map(BASE, STACK_SIZE)        # 主空间
mu.mem_map(STACK_ADDR, STACK_SIZE)  # 栈空间
mu.mem_write(BASE, read("./fibonacci")) # 映射到内存
mu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE - 1) # 初始化rsp


mu.hook_add(UC_HOOK_CODE, hook_code)

# 模拟执行代码
mu.emu_start(0x00000000004004E0, 0x0000000000400575)
print(flag)

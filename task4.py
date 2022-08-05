# -*- coding: UTF-8 -*-
from unicorn import *
from unicorn.x86_const import *
from unicorn.arm_const import *

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

# 构造对应平台的模拟器
mu          =   Uc(UC_ARCH_ARM, UC_MODE_LITTLE_ENDIAN)
BASE        =   0x10000 
STACK_ADDR  =   0x300000        # 栈的地址不能太小为0, 不然会有内存访问问题.
STACK_SIZE  =   1024 * 1024

ENTRY       =   0x104D0
EXIT        =   0x10580

# 分配内存 和 栈空间
mu.mem_map(BASE, STACK_SIZE)        # 主空间
mu.mem_map(STACK_ADDR, STACK_SIZE)  # 栈空间

# 载入镜像
mu.mem_write(BASE, read("./task4"))
mu.reg_write(UC_ARM_REG_SP, STACK_ADDR + int(STACK_SIZE /2)) # 初始化rsp

io_map      =   {}  # 保存输入对应的返回值
inputs      =   []
# last_input  =   0   # 不能通过这种方式, 因为函数存在递归调用, 会修改参数

def hook_code(mu:Uc, address, size, user_data): 
    global last_input
    if address == ENTRY:
        # print("on enter ")
        a0      =   mu.reg_read(UC_ARM_REG_R0)
        if io_map.get(a0):
            mu.reg_write(UC_ARM_REG_R0, io_map.get(a0))
            mu.reg_write(UC_ARM_REG_PC, 0x105BC)    # 不能用当前函数的 BX LR 因为已经被 hook
            # print("ret seend before {}".format(io_map.get(a0)))
        else:
            io_map[a0]  =   -1
            inputs.append(a0)
            # last_input  =   a0
            # print("new a0 = {}".format(a0))
    
    elif address == EXIT:
        # 缓存结果
        ret      =   mu.reg_read(UC_ARM_REG_R0)
        io_map[inputs.pop()]  =   ret
        # io_map[last_input]  =   ret
        # print("save ret {}".format(ret))

    # else:
    #     print("executing 0x%x" % address)


# hook 
mu.hook_add(UC_HOOK_CODE, hook_code)

# 模拟执行一段代码
mu.emu_start(0x010584,   0x000105A8)
ret = mu.reg_read(UC_ARM_REG_R1)

print("ret is {}".format(ret))

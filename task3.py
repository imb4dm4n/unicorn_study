from unicorn import *
from unicorn.x86_const import *
import struct
'''
让 super_function 返回1.
思路1: 指令hook, 遇到函数返回地址时, 修改 eax 的值为1就好了
思路2: 修改输入的参数
'''
def u32(data):
    return struct.unpack("I", data)[0]
 
def p32(num):
    return struct.pack("I", num)

def read(name):
    with open(name, 'rb') as f:
        return f.read()

BASE = 0x4000000
STACK_ADDR = 0x0
STACK_SIZE = 1024*1024
def hook_code(mu, address, size, user_data): 
    pass
 
mu = Uc (UC_ARCH_X86, UC_MODE_32)
 
mu.mem_map(BASE, 1024*1024)
mu.mem_map(STACK_ADDR, STACK_SIZE)
mu.mem_write(BASE, read("./function"))

esp = STACK_ADDR +int( STACK_SIZE/2)
string_addr = STACK_ADDR
mu.mem_write(string_addr, b"batman\x00")

# 初始化 esp
print("esp  = %x" % esp)
print("esp = 0x%x" % mu.reg_read(UC_X86_REG_ESP))
mu.reg_write(UC_X86_REG_ESP, esp)
print("esp = 0x%x" % mu.reg_read(UC_X86_REG_ESP))
mu.mem_write(esp + 4, p32(5))
mu.mem_write(esp + 8, p32(string_addr))


# 模拟执行代码
print("esp value = 0x%x" % u32(mu.mem_read(esp+0x4, 4)))
print("esp value1 = 0x{}".format(u32(mu.mem_read(esp+0x8, 4))))
addr = u32(mu.mem_read(esp+0x8, 4))
s = mu.mem_read(addr, 20).split(b"\x00")[0]   
print("str = {}".format(str(s)))

mu.emu_start(0x57b, 0x5b1)
return_value = mu.reg_read(UC_X86_REG_EAX)
print ("The returned value is: %d" % return_value)
print("esp = 0x%x" % mu.reg_read(UC_X86_REG_ESP))

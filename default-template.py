from pwn import *

binary_name = "{binary}"
exe  = ELF(binary_name, checksec=True)
libc = ELF("{libc}", checksec=False)
context.binary = exe

ru  = lambda *x: r.recvuntil(*x)
rl  = lambda *x: r.recvline(*x)
rc  = lambda *x: r.recv(*x)
sla = lambda *x: r.sendlineafter(*x)
sa  = lambda *x: r.sendafter(*x)
sl  = lambda *x: r.sendline(*x)
sn  = lambda *x: r.send(*x)

if args.REMOTE:
    r = connect("")
elif args.GDB:
    r = gdb.debug(f"{debug_dir}/{{binary_name}}", """
        c
    """, aslr=False)
else:
    r = process(f"{debug_dir}/{{binary_name}}")

{interactions}


r.interactive()

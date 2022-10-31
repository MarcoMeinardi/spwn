from pwn import *

binary_name = "{binary}"
exe  = ELF(binary_name, checksec=True)
libc = ELF("{libc}", checksec=False)
context.binary = exe

if args.REMOTE:
	r = connect("")
elif args.GDB:
	r = gdb.debug(f"{debug_dir}/{{binary_name}}", """
		c
	""")
else:
	r = process(f"{debug_dir}/{{binary_name}}")

{interactions}


r.interactive()
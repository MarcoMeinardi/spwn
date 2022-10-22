import spwn.utils as utils

# 0: binary name
# 1: libc name
template_loads_with_libc = '''
from pwn import *

binary_name = "{0}"
context.binary = binary_name
exe  = ELF(binary_name, checksec=False)
libc = ELF("{1}", checksec=False)
'''[1:]
template_loads_without_libc = '''
from pwn import *

binary_name = "{0}"
context.binary = binary_name
exe = ELF(binary_name, checksec=False)
'''[1:]

# 0: debug directory or '.' if no libc
# 1: interaction functions
template_start_program = '''
if args.REMOTE:
    r = connect("")
elif args.GDB:
    r = gdb.debug(f"{0}/{{binary_name}}", """
        c
    """)
else:
    r = process(f"{0}/{{binary_name}}")

{1}


r.interactive()
'''

class Scripter:
    def __init__(self, files):
        self.files = files
        

    def create_script(self, debug_dir: str) -> None:
        self.create_menu_interaction_functions()
        if self.files.libc:
            self.script  = template_loads_with_libc.format(self.files.binary.name, self.files.libc.name)
        else:
            debug_dir = '.'
            self.script  = template_loads_without_libc.format(self.files.binary.name)

        self.script += template_start_program.format(debug_dir, self.interactions)

    def save_script(self, output_file: str) -> None:
        with open(output_file, "w") as f:
            f.write(self.script)

    def create_menu_interaction_functions(self) -> None:
        self.interactions = ""
        menu_recvuntil = input("Menu recvuntil ( empty to skip interactions ) > ")[:-1]
        if not menu_recvuntil: return
        while True:
            fun_name = self.ask_function_name()
            if fun_name is None: break
            function = InteractionFunction(menu_recvuntil, fun_name)
            function.build()
            self.interactions += function.emit_function() + "\n"

    def ask_function_name(self) -> str | None:
        name = input("Function name > ")[:-1]
        return name if name else None


class InteractionFunction:
    def __init__(self, menu_recvuntil: str, name: str):
        self.menu_recvuntil = menu_recvuntil
        self.name = name
        self.variables = []

    def build(self) -> None:
        self.ask_menu_option()
        while self.ask_variable():
            ...

    def ask_menu_option(self) -> None:
        while True:
            self.menu_option = input("Menu option > ")[:-1]
            if self.menu_option: break
            print("[!] Cannot be empty")

    def ask_variable(self) -> bool:
        var_type = utils.ask_list("Variable type", ["int", "bytes"])
        if var_type is None: return False

        if var_type == "int":
            self.variables.append(IntVariable())
        elif var_type == "bytes":
            self.variables.append(ByteVariable())
        else:
            assert False, "???"
        
        return True

    def emit_function(self) -> str:
        function = f'def {self.name}({", ".join(v.name for v in self.variables)}):\n'
        function += f'\tr.sendlineafter(b"{self.menu_recvuntil}", b"{self.menu_option}")\n'
        for v in self.variables:
            function += f"\t{v.emit_interaction()}\n"

        return function


class AbstractVariable:
    def __init__(self):
        self.ask_name()
        self.ask_interaction()

    def ask_name(self) -> None:
        while True:
            self.name = input("Variable name > ")[:-1]
            if self.name: break
            print("[!] Cannot be empty")

    def ask_interaction(self) -> None:
        self.interaction = input("Send after > ")[:-1]
        self.interaction = self.interaction if self.interaction else None

class IntVariable(AbstractVariable):
    def __init__(self):
        super().__init__()

    def emit_interaction(self) -> str:
        if self.interaction:
            return f'r.sendlineafter(b"{self.interaction}", b"%d" % {self.name})'
        else:
            return f'r.sendline(b"%d" % {self.name})'


class ByteVariable(AbstractVariable):
    def __init__(self):
        super().__init__()

    def emit_interaction(self) -> str:
        if self.interaction:
            return f'r.sendlineafter(b"{self.interaction}", {self.name})'
        else:
            return f'r.sendline({self.name})'


        
    
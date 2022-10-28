from spwn.filemanager import FileManager
import spwn.utils as utils


class Scripter:
    def __init__(self, files: FileManager, template_filename: str, create_interactions: bool):
        self.files = files
        self.create_interactions = create_interactions
        self.interactions = ""
        with open(template_filename) as f:
            self.template = f.read()
        

    def create_script(self, debug_dir: str) -> None:
        if self.create_interactions:
            self.create_menu_interaction_functions()

        if self.files.libc:
            self.script = self.template.format(
                binary=self.files.binary.name,
                libc=self.files.libc.name,
                debug_dir=debug_dir,
                interactions=self.interactions
            )

        else:
            # Remove libc line from template
            lines = self.template.splitlines()
            ind = 0
            while ind < len(lines):
                if "{libc}" in lines[ind]:
                    del lines[ind]
                else:
                    ind += 1
            self.template = "\n".join(lines)

            self.script = self.template.format(
                binary=self.files.binary.name,
                debug_dir=".",
                interactions=self.interactions
            )


    def save_script(self, output_file: str) -> None:
        with open(output_file, "w") as f:
            f.write(self.script)

    def create_menu_interaction_functions(self) -> None:
        menu_recvuntil = input("Menu recvuntil > ")[:-1]
        if not menu_recvuntil: return
        while True:
            fun_name = self.ask_function_name()
            if fun_name is None: break
            function = InteractionFunction(menu_recvuntil, fun_name)
            function.build()
            self.interactions += function.emit_function() + "\n"

    def ask_function_name(self) -> str | None:
        name = input("Function name ( Empty to end ) > ")[:-1]
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
        var_type = utils.ask_list("Variable type", ["int", "bytes"], "( Empty to end function )")
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


        
    
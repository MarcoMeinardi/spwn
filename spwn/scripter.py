from spwn.filemanager import FileManager
from spwn.configmanager import ConfigManager
import spwn.utils as utils


class Scripter:
	def __init__(self, configs: ConfigManager, files: FileManager | None = None, create_interactions: bool = False):
		self.interactions = ""
		self.configs = configs
		if files:
			self.files = files
			self.create_interactions = create_interactions
			with open(self.configs.template_file) as f:
				self.template = f.read()

	def create_script(self) -> None:
		if self.create_interactions:
			if "{interactions}" not in self.template:
				print("[!] Template does not contain {interactions} placeholder")
			else:
				self.create_menu_interaction_functions()

		if self.files.libc:
			self.script = self.template.format(
				binary=self.files.binary.name,
				libc=self.files.libc.name,
				debug_dir=self.configs.debug_dir,
				interactions=self.interactions
			)

		else:
			# Remove libc line from template
			self.template = "\n".join(filter(lambda x: "{libc}" not in x, self.template.splitlines()))

			self.script = self.template.format(
				binary=self.files.binary.name,
				debug_dir=".",
				interactions=self.interactions
			)

	def save_script(self) -> None:
		with open(self.configs.script_file, "w") as f:
			f.write(self.script)

	def dump_interactions(self):
		print()
		print("-" * 50)
		print(self.interactions, end='')
		print("-" * 50)

	def create_menu_interaction_functions(self) -> None:
		menu_recvuntil = input("Menu recvuntil > ")
		if not menu_recvuntil: return
		while True:
			fun_name = self.ask_function_name()
			if fun_name is None: break
			function = InteractionFunction(self.configs, menu_recvuntil, fun_name)
			function.build()
			self.interactions += function.emit_function() + "\n"

	def ask_function_name(self) -> str | None:
		name = input("Function name ( Empty to end ) > ")
		return name if name else None


class InteractionFunction:
	def __init__(self, configs: ConfigManager, menu_recvuntil: str, name: str):
		self.configs = configs
		self.menu_recvuntil = menu_recvuntil
		self.name = name
		self.variables = []

	def build(self) -> None:
		self.ask_menu_option()
		while self.ask_variable():
			...

	def ask_menu_option(self) -> None:
		while True:
			self.menu_option = input("Menu option > ")
			if self.menu_option: break
			print("[!] Cannot be empty")

	def ask_variable(self) -> bool:
		variable_name = utils.ask_string("Variable name ( Empty to end function )", can_skip=True)
		if not variable_name: return False
		variable_type = utils.ask_list("Variable type", ["int", "bytes"], can_skip=False)
		variable_interaction = utils.ask_string("Send after", can_skip=False)

		if variable_type == "int":
			self.variables.append(IntVariable(self.configs, variable_name, variable_interaction))
		elif variable_type == "bytes":
			self.variables.append(ByteVariable(self.configs, variable_name, variable_interaction))
		else:
			assert False, "???"

		return True

	def emit_function(self) -> str:
		function = f'def {self.name}({", ".join(v.name for v in self.variables)}):\n'
		function += f'{self.configs.tab}{self.configs.pwn_process}.sendlineafter(b"{self.menu_recvuntil}", b"{self.menu_option}")\n'
		for v in self.variables:
			function += f"{self.configs.tab}{v.emit_interaction()}\n"

		return function


class AbstractVariable:
	def __init__(self, configs: ConfigManager, name: str, interaction: str):
		self.configs = configs
		self.name = name
		self.interaction = interaction


class IntVariable(AbstractVariable):
	def __init__(self, configs: ConfigManager, name: str, interaction: str):
		super().__init__(configs, name, interaction)

	def emit_interaction(self) -> str:
		if self.interaction:
			return f'{self.configs.pwn_process}.sendlineafter(b"{self.interaction}", b"%d" % {self.name})'
		else:
			return f'{self.configs.pwn_process}.sendline(b"%d" % {self.name})'


class ByteVariable(AbstractVariable):
	def __init__(self, configs: ConfigManager, name: str, interaction: str):
		super().__init__(configs, name, interaction)

	def emit_interaction(self) -> str:
		if self.interaction:
			return f'{self.configs.pwn_process}.sendlineafter(b"{self.interaction}", {self.name})'
		else:
			return f'{self.configs.pwn_process}.sendline({self.name})'

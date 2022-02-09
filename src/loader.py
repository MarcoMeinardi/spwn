from library import Library

class Loader(Library):
	def __init__(self, file_name, libc):
		super().__init__(file_name)
		self.libc = libc

	def download_loader(self, output_directory):
		'''
		Download a loader from ubuntu packages to run the binary with the given libc
		'''
		package_name = f"libc6_{self.libc.ubuntu_version}_{self.libc.pwn_libc.get_machine_arch()}.deb"
		package_url = "https://launchpad.net/ubuntu/+archive/primary/+files/" + package_name
		loader_name = f"ld-{self.libc.libc_number}.so"
		return self.download_package(output_directory, package_name, package_url, loader_name, "ld-linux.so.2")
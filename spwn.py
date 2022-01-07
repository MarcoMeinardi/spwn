#!/bin/python
import pwnlib.libcdb
import os
import platform
import re
import requests
import tempfile
import libarchive.public
import tarfile
import shutil


debug_dir = "debug"

# 0: binary
# 1: original libc
# 2: debug directory
base_script = \
'''from pwn import *
context.binary = "./{0}"
exe = ELF("./{0}", checksec = False)
libc = ELF("./{1}", checksec = False)

if args.REMOTE:
	r = connect("")
elif args.GDB:
	r = gdb.debug("./{2}/{0}", """
		c
	""", aslr = False)
elif args.ORIGINAL:
	r = process("./{0}", env = {{"LD_PRELOAD": "./{1}"}})
else:
	r = process("./{2}/{0}")




r.interactive()
'''

def create_script(binary, libc):
	global debug_dir
	script = base_script.format(binary, libc, debug_dir)
	with open("./a.py", "w") as f:
		f.write(script)

def find_binaries():
	files = os.listdir()
	libc = None
	loader = None
	binary = None
	for file in files:
		if file.startswith("libc"):
			libc = file
		elif file.startswith("ld"):
			loader = file
		else:
			binary = file

	if binary is None:
		print("[ERROR] Binary not found")
		quit()
	if libc is None:
		print("[ERROR] libc not found")
		quit()

	return binary, libc, loader

def basic_info(binary):
	print(f"[*] file ./{binary}")
	os.system(f"file ./{binary}")
	print(f"[*] pwn checksec ./{binary}")
	os.system(f"pwn checksec ./{binary}")

def get_architecture(binary):
	available_architectures = {
		"32bit": "i386",
		"64bit": "amd64"
	}
	bits = platform.architecture(binary)[0]
	return available_architectures[bits]

def get_libc_version(libc):
	with open(libc, "r", encoding = "latin-1") as f:
		version = re.search(r"\d+\.\d+-\d+ubuntu\d+\.\d+", f.read()).group(0)
	return version

def create_debug_directory():
	global debug_dir
	while os.path.exists(f"./{debug_dir}"):
		print(f"[!] \"{debug_dir}\" directory already exists, enter another name for the debug directory or press enter")
		inp = input("> ").strip()
		if not inp:
			return
		debug_dir = inp

	os.mkdir(debug_dir)

def copy_binary(binary):
	shutil.copyfile(f"./{binary}", f"./{debug_dir}/{binary}")

def get_loader(libc_version, architecture):
	global debug_dir

	package_name = f"libc6_{libc_version}_{architecture}.deb"
	package_url = "https://launchpad.net/ubuntu/+archive/primary/+files/" + package_name

	r = requests.get(package_url)
	if r.status_code != 200:
		print(f"[ERROR] Cannot get debug package from {package_url} (error {r.status_code})")
		quit()

	with open(f"{debug_dir}/{package_name}", "wb") as f:
		f.write(r.content)

	sub_archive_name = "data.tar.xz"

	with libarchive.public.file_reader(f"{debug_dir}/{package_name}") as archive:
		for entry in archive:
			if sub_archive_name in str(entry):
				with open(f"{debug_dir}/{sub_archive_name}", "wb") as sub_archive:
					for block in entry.get_blocks():
						sub_archive.write(block)
				break

	os.remove(f"{debug_dir}/{package_name}")

	libc_number = re.search(r"\d+\.\d+", libc_version).group(0)
	debug_loader_name = f"ld-{libc_number}.so"
	data_archive = tarfile.open(f"{debug_dir}/{sub_archive_name}", "r")

	for file_name in data_archive.getnames():
		if debug_loader_name in file_name:
			loader = data_archive.extractfile(file_name)
			break

	with open(f"{debug_dir}/ld-linux.so.2", "wb") as f:
		f.write(loader.read())

	os.remove(f"{debug_dir}/{sub_archive_name}")

def get_debug_libc(libc, libc_version, architecture):
	global debug_dir
	shutil.copyfile(libc, f"{debug_dir}/libc.so.6")
	# pwnlib.libcdb.unstrip_libc(f"{debug_dir}/libc.so.6") # wait for it to be added to the pip archive

def set_executable(*args):
	global debug_dir
	for file_name in args:
		os.chmod(file_name, 0o777)

def set_runpath(binary):
	global debug_dir
	os.system(f"patchelf {debug_dir}/{binary} --set-rpath ./{debug_dir}/")


binary, libc, loader = find_binaries()
basic_info(binary)
architecture = get_architecture(libc)
libc_version = get_libc_version(libc)

create_debug_directory()
copy_binary(binary)
get_loader(libc_version, architecture)
get_debug_libc(libc, libc_version, architecture)

set_executable(
	f"./{debug_dir}/{binary}",
	f"./{debug_dir}/ld-linux.so.2",
	f"./{binary}"
)
set_runpath(binary)

create_script(binary, libc)
os.system("subl a.py")
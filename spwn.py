#!/usr/bin/python
import os, sys
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
	script = base_script.format(binary, libc, debug_dir)
	with open("./a.py", "w") as f:
		f.write(script)

def find_binaries():
	files = os.listdir()
	libc = None
	loader = None
	binaries = []
	for file_name in files:
		if file_name.startswith("libc"):
			libc = file_name
		elif file_name.startswith("ld"):
			loader = file_name
		else:
			if not file_name.startswith(".") and not os.path.isdir(file_name):
				binaries.append(file_name)

	if len(binaries) == 0:
		print("[ERROR] Binary not found")
		quit()
	if libc is None:
		print("[ERROR] libc not found")
		quit()

	if len(binaries) == 1:
		binary = binaries[0]
	else:
		print("[!] More than one candidate for binary:")
		for i, file_name in enumerate(binaries):
			print(f"{i}: {file_name}")
		while True:
			try:
				index = int(input("> "))
				binary = binaries[index]
				break
			except:
				print("[!] Invalid index")

	return binary, libc, loader

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

def basic_info(binary, libc_version):
	print(f"[*] file ./{binary}")
	os.system(f"file ./{binary}")
	print(f"[*] pwn checksec ./{binary}")
	os.system(f"pwn checksec ./{binary}")
	libc_number = re.search(r"\d+\.\d+", libc_version).group(0)
	print(f"[*] libc {libc_number}")

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

def get_debug_loader(libc_version, architecture):
	package_name = f"libc6_{libc_version}_{architecture}.deb"
	package_url = "https://launchpad.net/ubuntu/+archive/primary/+files/" + package_name

	r = requests.get(package_url)
	if r.status_code != 200:
		print(f"[ERROR] Cannot get debug package from {package_url} (error {r.status_code})")
		quit()

	with open(f"{debug_dir}/{package_name}", "wb") as f:
		f.write(r.content)

	with libarchive.public.file_reader(f"{debug_dir}/{package_name}") as archive:
		for entry in archive:
			if "data.tar.xz" in str(entry):
				with open(f"{debug_dir}/data.tar.xz", "wb") as sub_archive:
					for block in entry.get_blocks():
						sub_archive.write(block)
				break

	os.remove(f"{debug_dir}/{package_name}")

	libc_number = re.search(r"\d+\.\d+", libc_version).group(0)
	loader_name = f"ld-{libc_number}.so"
	data_archive = tarfile.open(f"{debug_dir}/data.tar.xz", "r")

	for file_name in data_archive.getnames():
		if loader_name in file_name:
			loader_file = data_archive.extractfile(file_name)
			break

	with open(f"{debug_dir}/ld-linux.so.2", "wb") as f:
		f.write(loader_file.read())

	os.remove(f"{debug_dir}/data.tar.xz")

def get_debug_libc(libc, libc_version, architecture):
	package_name = f"libc6-dbg_{libc_version}_{architecture}.deb"
	package_url = "https://launchpad.net/ubuntu/+archive/primary/+files/" + package_name

	r = requests.get(package_url)
	if r.status_code != 200:
		print(f"[ERROR] Cannot get debug package from {package_url} (error {r.status_code})")
		quit()

	with open(f"{debug_dir}/{package_name}", "wb") as f:
		f.write(r.content)

	with libarchive.public.file_reader(f"{debug_dir}/{package_name}") as archive:
		for entry in archive:
			if "data.tar.xz" in str(entry):
				with open(f"{debug_dir}/data.tar.xz", "wb") as sub_archive:
					for block in entry.get_blocks():
						sub_archive.write(block)
				break

	os.remove(f"{debug_dir}/{package_name}")

	libc_number = re.search(r"\d+\.\d+", libc_version).group(0)
	debug_libc_name = f"libc-{libc_number}.so"
	data_archive = tarfile.open(f"{debug_dir}/data.tar.xz", "r")

	for file_name in data_archive.getnames():
		if debug_libc_name in file_name:
			libc_file = data_archive.extractfile(file_name)
			break

	with open(f"{debug_dir}/libc.so.6", "wb") as f:
		f.write(libc_file.read())

	os.system(f"eu-unstrip ./{libc} ./{debug_dir}/libc.so.6")
	os.remove(f"{debug_dir}/data.tar.xz")

def set_executable(*args):
	for file_name in args:
		os.chmod(file_name, 0o777)

def set_runpath(binary):
	os.system(f"patchelf {debug_dir}/{binary} --set-rpath ./{debug_dir}/ --set-interpreter ./{debug_dir}/ld-linux.so.2")

binary, libc, loader = find_binaries()
architecture = get_architecture(libc)
libc_version = get_libc_version(libc)
basic_info(binary, libc_version)

create_debug_directory()
copy_binary(binary)
get_debug_loader(libc_version, architecture)
get_debug_libc(libc, libc_version, architecture)

set_executable(
	f"./{debug_dir}/{binary}",
	f"./{debug_dir}/libc.so.6",
	f"./{debug_dir}/ld-linux.so.2",
	f"./{binary}"
)
set_runpath(binary)

create_script(binary, libc)
os.system("subl a.py")
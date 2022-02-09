#!/usr/bin/env python3
from pwn import *
import os, sys
import platform
import re
import requests
import tarfile
import shutil

debug_dir = "debug"

# 0: binary
# 1: original libc
# 2: debug directory
script_prefix = \
'''from pwn import *
context.binary = "./{0}"
exe = ELF("./{0}", checksec = False)
'''
base_script_libc = \
'''
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
base_script_no_libc = \
'''
if args.REMOTE:
	r = connect("")
elif args.GDB:
	r = gdb.debug("./{0}", """
		c
	""", aslr = False)
else:
	r = process("./{0}")




r.interactive()
'''

def create_script(binary, libc = None, gadgets = None):
	script = script_prefix
	if libc is None:
		if gadgets is not None:
			script += "\n" + gadgets
		script += base_script_no_libc
		script = script.format(binary)
	else:
		script += 'libc = ELF("./{2}/libc.so.6", checksec = False)\n'
		if gadgets is not None:
			script += "\n" + gadgets
		script += base_script_libc
		script = script.format(binary, libc, debug_dir)
		
	exploit_name = "a.py"
	while os.path.exists(f"./{exploit_name}"):
		print(f"[!] \"{exploit_name}\" already exists, type in a new name or press enter to overwrite it")
		inp = input("> ").strip()
		if not inp:
			break
		exploit_name = inp

	with open(f"./{exploit_name}", "w") as f:
		f.write(script)
	return exploit_name

def manual_selection(files):
	files = [file for file in files if platform.architecture(file)[1] == "ELF"]
	if not files:
		print("[ERROR] No ELF found")
		quit()

	binary, libc, loader = None, None, None
	print("[*] Enter binary")
	for i, file_name in enumerate(files):
		print(f"{i}: {file_name}")
	while binary is None:
		try:
			index = int(input("> ").strip())
			binary = files[index]
		except KeyboardInterrupt:
			quit()
		except:
			print("[!] Invalid index")

	files.remove(binary)
	if not files:
		return binary, None, None
	print("[*] Enter libc or press enter if there isn't")
	for i, file_name in enumerate(files):
		print(f"{i}: {file_name}")
	while libc is None:
		try:
			inp = input("> ").strip()
			if not inp: break
			index = int(inp)
			libc = files[index]
		except KeyboardInterrupt:
			quit()
		except:
			print("[!] Invalid index")
	
	if libc is not None:
		files.remove(libc)
		if not files:
			return binary, libc, None
		print("[*] Enter loader or press enter if there isn't")
		for i, file_name in enumerate(files):
			print(f"{i}: {file_name}")
		while loader is None:
			try:
				inp = input("> ").strip()
				if not inp: break
				index = int(inp)
				loader = files[index]
			except KeyboardInterrupt:
				quit()
			except:
				print("[!] Invalid index")

	return binary, libc, loader

def find_files():
	files = os.listdir()
	libc = None
	loader = None
	binaries = []
	for file_name in files:
		if platform.architecture(file_name)[1] != "ELF":
			continue
		if file_name.startswith("libc"):
			libc = file_name
		elif file_name.startswith("ld.") or file_name.startswith("ld-"):
			loader = file_name
		else:
			binaries.append(file_name)

	if len(binaries) == 0:
		print("[!] Binary not found, continuing with manual selection")
		return manual_selection(files)

	if len(binaries) == 1:
		binary = binaries[0]
	else:
		print("[!] More than one candidate for binary:")
		for i, file_name in enumerate(binaries):
			print(f"{i}: {file_name}")
		while True:
			try:
				index = int(input("> ").strip())
				binary = binaries[index]
				break
			except KeyboardInterrupt:
				quit()
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
		match = re.search(r"\d+\.\d+-\d+ubuntu\d+(\.\d+)?", f.read())
		if match:
			version = match.group()
		else:
			print("[ERROR] Cannot get libc version")
			quit()
	return version

def basic_info(binary, libc_version = None):
	print(f"[*] file ./{binary}")
	os.system(f"file ./{binary}")
	print(f"[*] pwn checksec ./{binary}")
	os.system(f"pwn checksec ./{binary}")
	if libc_version:
		libc_number = re.search(r"\d\.\d+", libc_version).group()
		print(f"[*] libc {libc_number}")

def find_possible_vulnerabilities(exe):
	maybe_vulnerable = ["gets", "__isoc99_scanf", "printf", "execve", "system"]
	found = []
	for function in maybe_vulnerable:
		if function in exe.symbols:
			found.append(function)
	
	if found:
		print("[*] There are some risky functions:")
		print(*found)

def create_debug_directory():
	global debug_dir
	while os.path.exists(f"./{debug_dir}"):
		print(f"[!] \"{debug_dir}\" directory already exists, type in a new name or press enter to use it anyways")
		inp = input("> ").strip()
		if not inp:
			return
		debug_dir = inp

	os.mkdir(debug_dir)

def copy_binary(binary):
	shutil.copyfile(f"./{binary}", f"./{debug_dir}/{binary}")

def get_loader(libc_version, architecture):
	package_name = f"libc6_{libc_version}_{architecture}.deb"
	package_url = "https://launchpad.net/ubuntu/+archive/primary/+files/" + package_name

	r = requests.get(package_url)
	if r.status_code != 200:
		print(f"[ERROR] Cannot get debug package from {package_url} (error {r.status_code})")
		quit()

	with open(f"{debug_dir}/{package_name}", "wb") as f:
		f.write(r.content)

	os.system(f"ar x {debug_dir}/{package_name} --output={debug_dir}")
	os.remove(f"{debug_dir}/control.tar.xz")
	os.remove(f"{debug_dir}/debian-binary")
	os.remove(f"{debug_dir}/{package_name}")

	libc_number = re.search(r"\d\.\d+", libc_version).group()
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

	os.system(f"ar x {debug_dir}/{package_name} --output={debug_dir}")
	os.remove(f"{debug_dir}/control.tar.gz")
	os.remove(f"{debug_dir}/debian-binary")
	os.remove(f"{debug_dir}/{package_name}")

	libc_number = re.search(r"\d\.\d+", libc_version).group()
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

def check_seccomp(binary, exe):
	for symbol in exe.symbols:
		if "seccomp" in symbol or "prctl" in symbol:
			break
	else:
		return

	print("[*] Possible seccomp detected")
	print(f"[*] timeout 1 seccomp-tools dump ./{binary}")
	os.system(f"timeout 1 seccomp-tools dump ./{binary}")

def get_rop_gadgets(binary, file_name):
	os.system(f"ROPgadget --binary {binary} --multibr > {file_name}")
	interesting_gadgets = [
		r"0x[0-9a-fA-F]+ : pop [a-z0-9]{2,4} ; ret\n",
		r"0x[0-9a-fA-F]+ : xchg [a-z0-9]{2,4}, [a-z0-9]{2,4} ; ret\n",
		r"0x[0-9a-fA-F]+ : ret\n",
		r"0x[0-9a-fA-F]+ : syscall ; ret\n",
		r"0x[0-9a-fA-F]+ : syscall\n"
	]

	with open(file_name, "r") as f:
		ropgadgets = f.read()
	gadgets = ""
	for interesting_gadget in interesting_gadgets:
		ropgadgets_copy = ropgadgets
		syscall_gadget = False
		while gadget := re.search(interesting_gadget, ropgadgets_copy): # python regex sucks and doesn't match every case
			ropgadgets_copy = ropgadgets_copy[gadget.span()[1]:]
			gadget = gadget.group()
			address, gadget_name = gadget.split(":")
			gadget_name = gadget_name[1:-1].upper()
			gadget_name = re.sub(r"( ; |, | )", "_", gadget_name)
			if "libc" in file_name:
				gadget_name = "LIBC_" + gadget_name
			address = address[:-1]
			gadgets += f"{gadget_name} = {address}\n"

			if "syscall" in gadget: # avoid writing both syscall and syscall ret
				syscall_gadget = True
				break
		if syscall_gadget: break
	
	return gadgets

binary, libc, loader = find_files()
rop = "rop" in sys.argv
exe = ELF(binary, checksec = False)
if libc:
	architecture = get_architecture(libc)
	libc_version = get_libc_version(libc)
	basic_info(binary, libc_version)
	find_possible_vulnerabilities(exe)

	create_debug_directory()
	copy_binary(binary)
	if loader is None:
		get_loader(libc_version, architecture)
	else:
		shutil.copyfile(loader, f"./{debug_dir}/ld-linux.so.2")
	get_debug_libc(libc, libc_version, architecture)

	set_executable(
		f"./{debug_dir}/{binary}",
		f"./{debug_dir}/libc.so.6",
		f"./{debug_dir}/ld-linux.so.2",
		f"./{binary}"
	)
	set_runpath(binary)
	check_seccomp(f"{debug_dir}/{binary}", exe)
	if rop:
		binary_gadgets = get_rop_gadgets(binary, "gadgets")
		libc_gadgets = get_rop_gadgets(libc, "libc-gadgets")
		exploit_name = create_script(binary, libc, binary_gadgets + "\n" + libc_gadgets)
	else:
		exploit_name = create_script(binary, libc)

else:
	basic_info(binary)
	find_possible_vulnerabilities(exe)
	set_executable(f"./{binary}")
	check_seccomp(binary, exe)
	if rop:
		binary_gadgets = get_rop_gadgets(binary, "gadgets")
		exploit_name = create_script(binary, None, binary_gadgets)
	else:
		exploit_name = create_script(binary)

os.system(f"subl {exploit_name}")
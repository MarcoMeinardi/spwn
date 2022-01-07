from pwn import *
import os
import platform
import re
import requests
import tempfile
import libarchive.public
import tarfile
import shutil

debug_dir = "debug"

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
		log.error("Binary not found")
	if libc is None:
		log.error("libc not found")

	return binary, libc, loader

def basic_info(binary):
	log.info(f"file ./{binary}")
	os.system(f"file ./{binary}")
	log.info(f"pwn checksec ./{binary}")
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
	log.info("Creating debug directory")
	while os.path.exists(f"./{debug_dir}"):
		log.warning(f"\"{debug_dir}\" directory already exists, enter another name for the debug directory or press enter")
		inp = input("> ").strip()
		if not inp:
			return
		debug_dir = inp

	os.mkdir(debug_dir)

def copy_binary(binary):
	shutil.copyfile(f"./{binary}", f"./{debug_dir}/{binary}")
	return binary

def download_package(libc_version, architecture):
	global debug_dir

	package_name = f"libc6-dbg_{libc_version}_{architecture}.deb"
	package_url = "https://launchpad.net/ubuntu/+archive/primary/+files/" + package_name

	log.info("Fetching debug package")
	r = requests.get(package_url)
	if r.status_code != 200:
		log.error(f"Cannot get debug package from {package_url} (error {r.status_code})")

	with open(f"{debug_dir}/{package_name}", "wb") as f:
		f.write(r.content)

	log.info("Extracting data archive")
	sub_archive_name = "data.tar.xz"

	with libarchive.public.file_reader(f"{debug_dir}/{package_name}") as archive:
		for entry in archive:
			if sub_archive_name in str(entry):
				with open(f"{debug_dir}/{sub_archive_name}", "wb") as sub_archive:
					for block in entry.get_blocks():
						sub_archive.write(block)
				break

	os.remove(f"{debug_dir}/{package_name}")


def get_loader(libc_version, architecture):
	global debug_dir
	log.info("Extracting debug loader")
	archive_name = "data.tar.xz"
	libc_number = re.search(r"\d+\.\d+", libc_version).group(0)
	loader_name = f"ld-{libc_number}.so"
	data_archive = tarfile.open(f"{debug_dir}/{archive_name}", "r")

	for file_name in data_archive.getnames():
		if loader_name in file_name:
			loader = data_archive.extractfile(file_name)
			break

	with open(f"{debug_dir}/{loader_name}", "wb") as f:
		f.write(loader.read())

	return loader_name

def get_debug_libc(libc_version, architecture):
	global debug_dir
	log.info("Extracting debug libc")
	archive_name = "data.tar.xz"
	libc_number = re.search(r"\d+\.\d+", libc_version).group(0)
	debug_libc_name = f"libc-{libc_number}.so"
	data_archive = tarfile.open(f"{debug_dir}/{archive_name}", "r")

	for file_name in data_archive.getnames():
		if debug_libc_name in file_name:
			loader = data_archive.extractfile(file_name)
			break

	with open(f"{debug_dir}/{debug_libc_name}", "wb") as f:
		f.write(loader.read())

	return debug_libc_name

def remove_debug_archive():
	global debug_dir
	os.remove(f"{debug_dir}/data.tar.xz")

def set_executable(*args):
	global debug_dir
	for file_name in args:
		os.chmod(f"{debug_dir}/{file_name}", 0o777)

def set_runpath(binary):
	global debug_dir
	os.system(f"patchelf {debug_dir}/{binary} --set-rpath ./{debug_dir}/")

binary, libc, loader = find_binaries()
basic_info(binary)
architecture = get_architecture(libc)
libc_version = get_libc_version(libc)

create_debug_directory()
debug_binary = copy_binary(binary)
download_package(libc_version, architecture)
debug_loader = get_loader(libc_version, architecture)
debug_libc = get_debug_libc(libc_version, architecture)
remove_debug_archive()

set_executable(debug_binary, debug_libc, debug_loader)
set_runpath(debug_binary)

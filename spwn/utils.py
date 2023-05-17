import pwn
import requests
import os
import subprocess


def ask_list_delete(msg: str, options: list[str], can_skip: bool) -> str | None:
	if len(options) == 1 and not can_skip:
		ans = options[0]
		del options[0]
		return ans

	print(f"{msg}:")
	for n, op in enumerate(options):
		print(f"[{n + 1}] {op}")

	if can_skip:
		print("( Enter to skip )")

	while True:
		resp = input("> ").strip()
		if not resp and can_skip:
			return None

		if resp.isdigit():
			resp = int(resp) - 1
			if 0 <= resp < len(options):
				break

		print("[!] Invalid option")

	ans = options[resp]
	del options[resp]

	return ans


def ask_list(msg: str, options: list[str], can_skip: bool) -> str | None:
	if len(options) == 1:
		ans = options[0]
		return ans

	print(f"{msg}:")
	for n, op in enumerate(options):
		print(f"[{n + 1}] {op}")

	while True:
		resp = input("> ").strip()
		if not resp and can_skip:
			return None

		if resp.isdigit():
			resp = int(resp) - 1
			if 0 <= resp < len(options):
				break

		print("[!] Invalid option")

	ans = options[resp]
	del options[resp]

	return ans


def ask_string(msg: str, can_skip: bool) -> str | None:
	resp = input(f"{msg} > ")
	if resp: return resp
	elif can_skip: return None

	while True:
		print("[!] Canno be empty")
		resp = input("> ")
		if resp:
			return resp


def download_package(package_url: str, tempdir: str) -> bool:
	try:
		r = requests.get(package_url)
	except Exception:
		print(f"[!] Cannot get package from {package_url}")
		return False
	if r.status_code != 200:
		print(f"[!] Cannot get package from {package_url} ( ERROR: {r.status_code} )")
		return False

	with open(os.path.join(tempdir, "libc.deb"), "wb") as f:
		f.write(r.content)

	return True


def extract_deb(tempdir: str) -> bool:
	try:
		subprocess.check_call(["ar", "x", os.path.join(tempdir, "libc.deb"), "--output=" + tempdir])
		return True
	except subprocess.CalledProcessError:
		print("[!] Cannot extract .deb package")
		return False


def find_and_extract_data(tempdir: str) -> bool:
	to_extract = None
	for file in os.listdir(tempdir):
		if file.startswith("data."):
			to_extract = file
			break

	if to_extract is None:
		print("[!] Cannot find data archive")
		return False

	try:
		subprocess.check_call(["tar", "xf", os.path.join(tempdir, to_extract), "-C", tempdir])
	except subprocess.CalledProcessError:
		print("[!] Cannot extract data archive")
		return False

	return True


def find_loader(tempdir: str) -> str | None:
	for parent, dirs, files in os.walk(tempdir):
		for file in files:
			if not file.startswith("ld-linux"): continue
			file = os.path.join(parent, file)
			if os.path.isfile(file) and pwn.platform.architecture(file)[1] == "ELF":
				return file

	print("[!] Cannot find loader inside deb package")
	return None

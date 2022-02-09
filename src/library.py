import os
import requests
import tarfile

class Library:
	def __init__(self, file_name):
		self.file_name = file_name

	def download_package(self, output_directory, package_name, package_url, file_to_extract, output_file):
		'''
		Download a (ubuntu) package
		Used to get libc symbols and loader
		'''
		# Download package from ubuntu
		r = requests.get(package_url)
		if r.status_code != 200:
			print(f"[ERROR] Cannot get debug package from {package_url} (error {r.status_code})")
			return False

		with open(f"{output_directory}/{package_name}", "wb") as f:
			f.write(r.content)

		# Extract everything and throw away what we don't need (I could have done it with libarchive, but it's borken)
		os.system(f"ar x {output_directory}/{package_name} --output={output_directory}")
		if os.path.exists(f"{output_directory}/control.tar.gz"):
			os.remove(f"{output_directory}/control.tar.gz")
		if os.path.exists(f"{output_directory}/control.tar.xz"):
			os.remove(f"{output_directory}/control.tar.xz")
		os.remove(f"{output_directory}/debian-binary")
		os.remove(f"{output_directory}/{package_name}")

		# Extract the needed file from the data.tar.xz sub-archive
		data_archive = tarfile.open(f"{output_directory}/data.tar.xz", "r")
		for file_name in data_archive.getnames():
			if file_to_extract in file_name:
				extracted_file = data_archive.extractfile(file_name)
				break
		else:
			print(f"[ERROR] Cannot find {file_to_extract} in ubuntu package")
			return False
		
		with open(f"{output_directory}/{output_file}", "wb") as f:
			f.write(extracted_file.read())

		# Delete the sub-archive from which we extracted the file
		os.remove(f"{output_directory}/data.tar.xz")

		return True
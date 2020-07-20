import os
import sys
try:
	import pefile
	import argparse
	import requests
	from bs4 import BeautifulSoup
except ImportError as e:
	print("[-] One of the following module is not installed:")
	print("\t- bs4")
	print("\t- pefile")
	print("\t- argparse")
	print("\t- requests")
	sys.exit(1)

verbose = False
headers = set()


class FunctionInfo:
	Function: str = None
	Link: str = None
	Description: str = None
	Module: str = None
	Header: str = None
	Library: str = None
	Prototype: str = None

def get_exported_funtions(module: str):
	if (os.path.exists(module) == False):
		print("[-] Invalid module provided")
		return
	
	image = pefile.PE(module, fast_load=True)
	image.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])

	functions = list()
	for function in image.DIRECTORY_ENTRY_EXPORT.symbols:
		functions.append(function.name)
	return functions

def get_function_info(info: FunctionInfo):
	if (info.Function is None or info.Function == ""):
		print("[-] Invalid function provided")
		return False

	
	url = "https://docs.microsoft.com/api/search?search={}&locale=en-us&scoringprofile=search_for_en_us_a_b_test&facet=category&%24top=1".format(info.Function)
	if (verbose == True):
		print("[>] Searching: {}".format(info.Function))
	resp = requests.get(url)

	
	blob = resp.json()
	if (len(blob["results"]) < 1):
		if (verbose == True):
			print("[-] Unable to find documentation for {} ".format(info.Function))
		return False


	blob = blob["results"][0]
	info.Link = blob["url"]
	info.Description = blob["description"]
	resp = requests.get(info.Link)
	soup = BeautifulSoup(resp.text, "lxml")
	
	
	lib = soup.find("meta", {"name": "req.lib"})
	if (lib is None):
		return False
	info.Library = lib.get("content")


	dll = soup.find("meta", {"name": "req.dll"})
	if (dll is None):
		return False
	info.Module = dll.get("content")


	header = soup.find("meta", {"name": "req.header"})
	if (header is None):
		return False
	info.Header = header.get("content")
	headers.add(info.Header.lower())

	prototype = soup.find_all("code", {"class": "lang-cpp"})
	if (len(prototype) == 0):
		prototype = soup.find_all("code", {"class": "lang-c++"})

	if (len(prototype) != 0):
		info.Prototype = prototype[0].text
	else:
		return False
	return True
	

def add_documentation(info: FunctionInfo):
	content = ""
	content += "/// <summary>\n"
	content += "/// {}\n".format(info.Description)
	content += "/// Link:    {}\n".format(info.Link)
	content += "/// Header:  {}\n".format(info.Header)
	content += "/// Module:  {}\n".format(info.Module)
	content += "/// Library: {}\n".format(info.Library)
	content += "/// </summary>\n"
	return content
	
	
def add_prototype(info: FunctionInfo):
	prefix = (info.Module.split(".")[0]).lower()
	info.Prototype = info.Prototype.replace(info.Function, "{}${}".format(prefix, info.Function))
	
	return "__declspec(dllimport) {}\n".format(info.Prototype)


def main():
	print("")
	print("Build Windows headers for Cobalt Strike BOF")
	print("Copyright (C) 2020 LianSec")
	print("https://Liantech.net\n")
	print("disclaimer: ")
	print("This script do most of the heavy lifting but this is not 100% accurate.")
	print("If one function is missing, you can Google for the documentation.")
	print("Also, you will probably have to fix few bits and piece prior to compilation.\n")

	parser = argparse.ArgumentParser()
	parser.add_argument("-m", "--module", help="Module in which symbols will be extracted.", required=True)
	parser.add_argument("-o", "--outfile", help="Name of the file in which the functions' prototype will be written.", required=False)
	parser.add_argument("-v", "--verbose", help="Increase script verbosity.", required=False, action='store_true', default=False)
	args = parser.parse_args()

	if (args.verbose == True):
		verbose = True

	(head, tail) = os.path.split(args.module)
	module_name = tail
	module_path = args.module
	if (args.outfile is None):
		args.outfile = tail.split(".")[0] + ".h"


	functions = get_exported_funtions(module_path)
	

	content = ""
	failed = 0
	success = 0;

	print("[>] Exported functions: {}".format(len(functions)))
	for x in functions:
		if (x is None or "_" in x.decode()):
			failed += 1
			continue

		info = FunctionInfo()
		info.Function = x.decode()
		if (get_function_info(info) == False):
			failed += 1
			continue

		if (info.Module.lower() != module_name):
			failed += 1
			continue

		content += add_documentation(info)
		content += add_prototype(info)
		success += 1


	with open(args.outfile, "w") as file:
		file.write("#include <windows.h>\n")
		for header in headers:
			file.write("#include <{}>\n".format(header))

		macro = "_" + args.outfile.replace(".", "_").upper()
		file.write("#ifndef {}\n".format(macro))
		file.write("#define {}\n\n".format(macro))
		file.write(content)
		file.write("#endif // !{}".format(macro))

	print("[+] Functions defined: {}".format(success))
	print("[-] Functions skipped: {}\n".format(failed))
		
if __name__ == "__main__":
	main()

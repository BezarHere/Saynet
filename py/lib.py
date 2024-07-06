import os
from pathlib import Path

path = Path("output/cache")

max_creation_time_path = ""
max_creation_time = 0.0
for i in os.scandir(path):
	if not i.path.endswith('.o'):
		continue
	if not Path(i.path).name.startswith('saynet'):
		continue
	print("found ", i.path)
	if max_creation_time < i.stat().st_birthtime:
		max_creation_time_path = i.path
		max_creation_time = i.stat().st_birthtime

lib_path = "saynet.a"

if len(max_creation_time_path) > 0:
	print("-" * 16)
	print(f"compiling {max_creation_time_path}, ct={max_creation_time}")
	os.system(f"del {lib_path}")
	os.system(f"ar -rcsv \"{lib_path}\" {max_creation_time_path}")
	print("-" * 16)
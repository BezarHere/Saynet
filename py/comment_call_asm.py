
from dataclasses import dataclass
from io import StringIO
import re
from typing import Iterable


CALL_RE = re.compile(r"<(.+?)>")
CALL_BREAK_RE = re.compile(r"(.+?)(\+0[xX][0-9a-fA-F]+)?$")
FUNC_RE = re.compile(r"<(.+?)>:\s*?\n")


@dataclass
class Func:
	name: str
	span: tuple[int, int]
	line: int

def get_function_defs(source: str):
	last_find = 0
	line = 0

	for i in FUNC_RE.finditer(source):

		line += source.count('\n', last_find, i.span()[1])
		last_find = i.span()[1]

		yield Func(i[1], i.span(1), line)

def get_function_calls(source: str):
	for i in CALL_RE.finditer(source):
		func_break = CALL_BREAK_RE.search(i[1])

		if func_break[1][0] == '.':
			continue

		yield Func(func_break[1], i.span(1), 0)

def annotate_lines(source: str):
	last = 0
	str = StringIO()
	functions = tuple(get_function_calls(source))
	print(f"CCA: found {len(functions)} 'function' calls")

	line_table = {i.name: i for i in get_function_defs(source)}
	print(f"CCA: found {len(line_table)} 'function' definitions")

	# print(line_table)

	for i in functions:
		line_end = source.find('\n', i.span[1])
		str.write(source[last:line_end])

		func = i.name
		f_line = line_table.get(func, "not found")
		note_comment = f'\t ; {func} at line {f_line.line if isinstance(f_line, Func) else f_line}'

		str.write(note_comment)
		last = line_end
	
	str.write(source[last:])

	str.seek(0)
	return str.read()

with open("output/output.s", 'r') as f:
	source = f.read()
	with open("output/disassembly.s", 'w') as fw:
		fw.write(annotate_lines(source))


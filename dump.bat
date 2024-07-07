@echo off

SET EXE="./output/output.exe"

objdump -d -C -M intel -M notes -S --source-comment="; " --visualize-jumps -M reg-names-raw %EXE% > "./output/output.s"
rem objdump -d -C -M amd64 %EXE% > "./output/output.asm"

py py/comment_call_asm.py

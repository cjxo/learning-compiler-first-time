@echo off

if not exist ..\build mkdir ..\build

set CompilerOpts=/nologo /Z7 /Od /W4 /DCDEBUG

pushd ..\build
cl %CompilerOpts% ..\code\playground_main.c /link /out:compiler.exe
popd

set CompilerOpts=

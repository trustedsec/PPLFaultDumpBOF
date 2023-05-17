cl.exe /I ..\common /I ..\phnt\include /I ..\Utils /I ..\DumpShellcode /GS- /c /DUNICODE /DBOF  entry.c
mkdir ..\BOF
copy /y entry.obj ..\BOF\entry.obj
copy /y DumpShellcode.exe.shellcode ..\BOF\DumpShellcode.exe.shellcode
copy /y pplfault.cna ..\BOF\pplfault.cna
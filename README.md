# DynamicImports Obfuscation Transformative Pass - By AlSch092 @ Github
This project implements an LLVM transformative obfuscation module pass to protect dynamically resolved Windows system calls. It was developed using the new pass manager  

The project was built & tested using CMake with Visual Studio 2022 Build Tools, and was tested with LLVM/Clang version 20.1.3 on Windows 10 x64.  

Right now the pass looks for hardcoded function and variable names (using "contains" when possible) along with attributes, however you'll need to custom-build LLVM to add in these attributes in order for LLVM to properly work with them.  

## Folder Structure  

/DynamicImportsObfuscatorPass/  
├── Example.cpp  
├── DynamicImportObfuscatorPass.cpp  
├── CMakeLists.txt  
├── BuildAndRun.bat  
├── README.md  
└── /build/ (pass project files & built pass .dll)  

## Building the DynamicImportObfuscation Pass ("obf-dynimports"):  

The file `BuildAndRun.bat` is the recommended build method, and contains a full pipeline for building the pass - creating the IR from Example.cpp, transforming the IR, compiling and linking the transformed IR into an executable, along with running the final executable.  

A manual build process can be done by following these steps:  

1. `mkdir build`  
2. `cd build`  
3. `cmake -G "Visual Studio 17 2022" -A x64 ..`  
4. `cmake --build . --config Release --target DynamicImportObfuscatorPass`  

 ** If you get an error about.. "LINK : fatal error LNK1181: cannot open input file 'C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\DIA SDK\lib\amd64\diaguids.lib' (See [LLVM GitHub Issue #86250](https://github.com/llvm/llvm-project/issues/86250))  
a) Open `build/DynamicImportObfuscatorPass.sln` in Visual Studio  
b) Select "Release" under current build configuration  
c) Right click on the DynamicImportObfuscatorPass project -> Click Properties -> Linker -> Input  
d) Under "Additional Dependencies", remove any references/lines to lib/amd64/diaguids.lib  
e) Close Visual Studio (save changes when prompted) and run the command at 4. again, or build the pass from within Visual Studio  

## Running the pass  

Assuming you're still in the 'build' directory:  

`opt -load-pass-plugin="./Release/DynamicImportObfuscatorPass.dll" -passes="obf-dynimports" ../Example.ll -S -o ../Example_out.ll`    

This should give you a version of Example.ll with added obfuscation (Example_out.ll), which follows the three obfuscation requirements outlined in the original task.  

You can then compile and link Example_out.ll:  

`clang -O0 ../Example_out.ll -o ../Example.exe`  

## Output  

When running the pass on Example.ll, the following text should be displayed in the console:  
```
XOR'd string: NtQueryInformationProcess => ╤(æ╤rπE6@ºA¢ycÜùç╬╣╥┴±oÆ┐
XOR'd string: NtQuerySystemInformation => ╤(æ╤rπE,W▓ZîyKÇÿç╥ä┴┌√eÅ
XOR'd string: NtQueryVirtualMemory => ╤(æ╤rπE)G│Z£unú¢à╧¢┘
XOR'd string: NtQueryInformationThread => ╤(æ╤rπE6@ºA¢ycÜùç╬╜╚▄≈kà
XOR'd string: NtQueryVolumeInformationFile => ╤(æ╤rπE)A¡[äqKÇÿç╥ä┴┌√eÅè±£╥
XOR'd string: NtCreateSection => ╤(â╓r≡H→}ñM¥}mÇ
XOR'd string: NtCreateThread => ╤(â╓r≡H→z⌐\îuf
XOR'd string: NtCreateProcessEx => ╤(â╓r≡H→~│Aèqq¥╗É
XOR'd string: NtQueueApcThread => ╤(æ╤rΣY>^ózüfgÅÜ
XOR'd string: NtWriteVirtualMemory => ╤(ù╓~σY)G│Z£unú¢à╧¢┘
XOR'd string: NtReadVirtualMemory => ╤(Æ┴v⌡j▬\╡[êxOïôç╥É
AóKÜg string: NtOpenProcess => ╤(Å╘r l
Transformed import names!
Found g_ImportAddresses
Injected decryption logic for importName
Found a store to g_ImportAddresses!
Transformed the store instruction to import table to be XOR'd with the key: 9900550227890101106, which is stored in g_ImportAddresses!
Transformed GetImportAddresses function!
Modified index to i32 5565448 in call to GetImportAddress
Generated junk byte string: .byte 0xAB,0x0D,0xE0,0xFD,0xBF,0xB8,0x89,0x3F,0xEB,0x3F,0x0C,0x27,0xBE,0x92,0x68,0xEF,0x27,0xBE,0x8F,0x24,0x81,0xC2,0x35,0x6E,0x1C,0x6F,0x52,0x52,0xBD,0x9C,0x1C,0xD8,0x1D,0xBD,0x89,0xB6,0x65,0x89,0xEC,0x23,0x67,0xA0,0xED,0xE0,0x9F,0x96,0x7F,0xE6,0xE3,0x1A,0xEA,0xFA,0xF9,0xA0,0x67,0x28,0x0F,0x76,0xBD,0x05,0x9A,0x80,0x33,0x15,0x43,0x8A,0x76,0xA1,0x2C,0xD7,0x20,0xFC,0x02,0xA3,0xF6,0x76,0xF5,0xBC,0x91,0x53,0x23,0x8F,0xC1,0xF4,0xB3,0x5E,0xC2,0xB6,0x5E,0x41,0xE5,0x2D,0x89,0x7F,0x21,0xC9,0x9F,0xF3,0x7F,0x86
Transformed GetImportAddress function!
Rewrote store using result of GetImportAddress
Transformed CallImportFunction routine!
Pass ran successfully and made atleast one code transformation!
```

Obfuscation keys are randomized on each pass, so these values will likely be different each time the pass is run.    

## Impact of Transformations  

Several changes can be seen in the binary & assembler code produced by compiling & linking the transformed `Example_out.ll` file:  

1. No references to "NtQuery..." can be seen when viewing string references in a disassembler/debugger - their values are encrypted while running our pass, and decrypted versions only appear on the stack, local to the function they're used in  

2. A string decryption loop (random key for each character of the string) is added before the call to `GetProcAddress` in `GetImportAddresses` using manual unfolding  

3. Before storing import addresses into `g_ImportAddresses` in the `GetImportAddresses` function, the address is XORed with a random key (the full key is split into 2):   

00007FF60B791D77 | mov edx,eax                                                 |  
00007FF60B791D79 | shr rax,20                                                  |  
00007FF60B791D7D | xor edx,6A0FDAA0                                            | high32 & low32 of 64-bit key  
00007FF60B791D83 | xor eax,F71E3AD2                                            |  
00007FF60B791D88 | mov eax,eax                                                 |  
00007FF60B791D8A | shl rax,20                                                  |  
00007FF60B791D8E | mov edx,edx                                                 |  
00007FF60B791D90 | or rdx,rax                                                  |  
00007FF60B791D93 | lea rax,qword ptr ds:[7FF60B7D4380]                         |  
00007FF60B791D9A | mov qword ptr ds:[rax+rcx*8],rdx                            | <- move import address into `g_ImportAddresses`  

...will cause values being stored in `g_ImportAddresses` to be obfuscated. Decryption never occurs in-place (only onto a stack-allocated location), so the encrypted value is not changed after being set.  

4. Calls to any dynamic imports are not direct - after the encrypted address is fetched from `GetImportAddress`, it's XORed with a key and called from [RSP+0xB8]  

5. The function `GetImportAddress` has the `index` parameter randomly transformed to make mappings less obvious. All calls to `GetImportAddress` have their `index` parameter transformed (index = index * rng() + rng())  

6. An opaque predicate with 100 randomized junk bytes are added to `GetImportAddress` to help obfuscate the return value of the function  

7. No XOR instructions are used with full keys - they are either split into multiple instructions (OR + AND) or into high32 + low32 bits (XOR + XOR)  

## Result
This pass makes it harder for attackers to:  

1. Identify what system calls are being made when performing static analysis/reversing  
2. See resolved addresses in memory  
3. Trace dynamic imports back to API functions  

No fragments are left in program sections (.rdata, .data), all decrypted copies of the stored encrypted values are done on the stack.  

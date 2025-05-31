@echo off
setlocal ENABLEDELAYEDEXPANSION

:: === CONFIGURE ===
:: Path to LLVM/Clang tools (adjust if needed)
for /f "delims=" %%i in ('where clang 2^>nul') do (
    set "LLVM_BIN=%%~dpi"
    goto :found_llvm
)
echo [!] clang.exe not found in PATH. Set LLVM_BIN manually.
exit /b 1
:found_llvm

:: Manually set LLVM bin path if not on path
:: set LLVM_BIN=C:\LLVM\bin\
set CLANG=%LLVM_BIN%\clang.exe
set OPT=%LLVM_BIN%\opt.exe

:: Your plugin pass DLL (already built by CMake)
set PASS_DLL=build\Release\DynamicImportObfuscatorPass.dll

:: Test source file
set SRC=Example.cpp

:: Working files
set BC=Example.bc
set LL=Example.ll
set OUT_LL=Example_out.ll
set EXE=Example.exe

echo [1/5] Compiling %SRC% to LLVM IR...
%CLANG% -S -emit-llvm -O0 %SRC% -o %LL%
if not exist %LL% (
    echo [!] LLVM IR generation failed.
    exit /b 1
)

mkdir build 2>nul

cd /d build

:: Skip cmake if solution file already exists
if exist DynamicImportObfuscatorPass.sln (
    echo [!] Skipping CMake generation - solution already exists.
) else (
    echo [1/5] Generating pass plugin project files...
    cmake -G "Visual Studio 17 2022" -A x64 ..
    if errorlevel 1 (
        echo [!] CMake generation failed.
        exit /b 1
    )
)

cmake --build . --config Release --target DynamicImportObfuscatorPass
if errorlevel 1 (
    echo [!] Build failed.
    exit /b 1
)

cd /d ../

echo [2/5] Converting .ll to .bc...
%CLANG% -emit-llvm -c %LL% -o %BC%
if not exist %BC% (
    echo [!] .bc conversion failed.
    exit /b 1
)

echo [3/5] Running custom LLVM pass...
%OPT% -load-pass-plugin %PASS_DLL% -passes=module(obf-dynimports) -S %BC% -o %OUT_LL%
if not exist %OUT_LL% (
    echo [!] Pass failed or did not output.
    exit /b 1
)

echo [4/5] Building transformed executable...
%CLANG% %OUT_LL% -o %EXE%
if not exist %EXE% (
    echo [!] Executable link failed.
    exit /b 1
)

echo [5/5] Build finished, running output...
echo ----------------------------------------------------
%EXE%
echo ----------------------------------------------------

endlocal

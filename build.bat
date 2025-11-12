@echo off
REM Windows build script - Compiles Go code to EXE

echo Building Go decrypt executable for Windows...

REM Set output directory
set OUTPUT_DIR=.\exe

REM Create output directory
if not exist %OUTPUT_DIR% mkdir %OUTPUT_DIR%

REM Compile 64-bit EXE
echo Compiling 64-bit EXE...
set CGO_ENABLED=0
set GOOS=windows
set GOARCH=amd64
go build -ldflags="-s -w" -o %OUTPUT_DIR%\go_decrypt.exe main.go

if %ERRORLEVEL% EQU 0 (
    echo Build successful! EXE created at %OUTPUT_DIR%\go_decrypt.exe
) else (
    echo Build failed with error code %ERRORLEVEL%
    exit /b %ERRORLEVEL%
)

echo Done!
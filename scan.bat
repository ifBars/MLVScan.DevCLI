@echo off
setlocal

set "assembly=%~1"
set "interactive="
if not defined assembly (
    set "interactive=1"
    set /p "assembly=DLL path: "
)
if not defined assembly (
    echo No DLL path provided.
    if defined interactive pause
    exit /b 1
)

rem Remove quotes when a path is pasted into the prompt.
set "assembly=%assembly:"=%"
dotnet run --project "%~dp0MLVScan.DevCLI.csproj" --configuration Release -- "%assembly%" --verbose
set "result=%errorlevel%"
if defined interactive pause
exit /b %result%

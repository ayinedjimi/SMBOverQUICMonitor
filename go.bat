@echo off
REM Script de compilation pour SMBOverQUICMonitor
REM Ayi NEDJIMI Consultants

echo ====================================
echo Compilation de SMBOverQUICMonitor
echo ====================================
echo.

where cl.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Erreur: Compilateur MSVC non trouve.
    echo Veuillez executer ce script depuis "Developer Command Prompt for VS"
    pause
    exit /b 1
)

echo Compilation en cours...
cl.exe /EHsc /W4 /std:c++17 ^
    /D UNICODE /D _UNICODE ^
    /Fe:SMBOverQUICMonitor.exe ^
    SMBOverQUICMonitor.cpp ^
    comctl32.lib wevtapi.lib ws2_32.lib crypt32.lib shlwapi.lib user32.lib gdi32.lib shell32.lib

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ====================================
    echo Compilation reussie!
    echo Executable: SMBOverQUICMonitor.exe
    echo ====================================
    echo.
    echo IMPORTANT: Necessite privileges administrateur
    echo.
    if exist SMBOverQUICMonitor.obj del SMBOverQUICMonitor.obj
) else (
    echo.
    echo ====================================
    echo Echec de la compilation
    echo ====================================
    pause
    exit /b 1
)

pause

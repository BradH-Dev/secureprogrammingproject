@echo off
setlocal enabledelayedexpansion

REM Define the ports to close
set PORTS=12345 12346

REM Loop over each port and kill the associated processes
for %%p in (%PORTS%) do (
    for /f "tokens=5" %%a in ('netstat -aon ^| findstr :%%p') do (
        set PID=%%a
        taskkill /PID !PID! /F /T
    )
)

echo All specified processes have been terminated.



@echo off
REM Start the first server on port 12345
start cmd.exe /k python server.py 12345
timeout /T 1 /NOBREAK

REM Start the first client
start cmd.exe /k python client.py
timeout /T 1 /NOBREAK

REM Start the second server on port 12346
start cmd.exe /k python server.py 12346
timeout /T 1 /NOBREAK

REM Start the second client
start cmd.exe /k python client2.py
timeout /T 10 /NOBREAK

REM Open the first client again
start cmd.exe /k python client.py
timeout /T 1 /NOBREAK

REM Finally, open the second client again
start cmd.exe /k python client2.py
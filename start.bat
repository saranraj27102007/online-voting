@echo off
echo.
echo  ==========================================
echo   VoteSecure - Starting Server
echo  ==========================================
echo.

REM Check if node_modules exists
IF NOT EXIST "node_modules" (
    echo  [!] node_modules not found. Running npm install...
    echo.
    npm install
    echo.
)

echo  Starting server...
echo  Open your browser at: http://localhost:3000
echo.
node server.js

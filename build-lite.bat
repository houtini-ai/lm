@echo off
REM Build script for Houtini LM Lite

echo Building Houtini LM Lite...

REM Clean dist directory
echo Cleaning dist directory...
if exist dist rmdir /s /q dist

REM Compile TypeScript
echo Compiling TypeScript...
npx tsc -p tsconfig-lite.json

REM Add shebang
echo Adding shebang...
node add-shebang-lite.mjs

echo.
echo Build complete!
echo.
echo To use with Claude Desktop, add this to your config:
echo   "houtini-lm-lite": {
echo     "command": "node",
echo     "args": ["C:/MCP/houtini-lm/dist/index-lite.js"],
echo     "env": {
echo       "LM_STUDIO_URL": "http://localhost:1234"
echo     }
echo   }

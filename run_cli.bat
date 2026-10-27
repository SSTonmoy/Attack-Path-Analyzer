@echo off
cd /d "%~dp0"

if not exist ".venv\Scripts\activate.bat" (
    echo [ERROR] Virtual environment .venv not found.
    echo Please create the virtual environment first: python -m venv .venv
    pause
    exit /b 1
)

call .venv\Scripts\activate.bat

echo [INFO] Running Attack Path Analyzer CLI on data/sample_small.json...
python main.py --input data/sample_small.json --out output

if errorlevel 1 (
    echo [ERROR] Analysis failed.
    pause
    exit /b 1
)

echo [INFO] Analysis complete. Opening output artifacts...
if exist "output\graph.png" start "" "output\graph.png"
if exist "output\report.md" start "" "output\report.md"

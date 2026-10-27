@echo off
cd /d "%~dp0"

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python 3.11 or later and ensure it is added to your PATH.
    pause
    exit /b 1
)

if not exist ".venv\Scripts\activate.bat" (
    echo [INFO] Virtual environment not found. Creating .venv...
    python -m venv .venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
)

call .venv\Scripts\activate.bat

python -c "import networkx, matplotlib" >nul 2>&1
if errorlevel 1 (
    echo [INFO] Required packages missing. Installing quietly from requirements.txt...
    python -m pip install -q -r requirements.txt
    if errorlevel 1 (
        echo [ERROR] Failed to install requirements from requirements.txt.
        pause
        exit /b 1
    )
)

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

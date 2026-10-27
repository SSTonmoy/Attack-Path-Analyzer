@echo off
cd /d "%~dp0"

if not exist ".venv\Scripts\activate.bat" (
    echo [ERROR] Virtual environment .venv not found.
    echo Please create the virtual environment first: python -m venv .venv
    pause
    exit /b 1
)

call .venv\Scripts\activate.bat

python -c "import streamlit" 2>nul
if errorlevel 1 (
    echo [INFO] Streamlit is missing. Installing requirements from requirements.txt...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo [ERROR] Failed to install requirements.
        pause
        exit /b 1
    )
)

echo [INFO] Launching Attack Path Analyzer web application...
streamlit run app.py

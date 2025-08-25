@echo off
echo Installing dependencies...
pip install -r requirements.txt

echo.
echo Starting Flask Chat Application...
echo.
echo The application will be available at: http://localhost:5000
echo Press Ctrl+C to stop the application
echo.

python app.py

pause

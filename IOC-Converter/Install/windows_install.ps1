# Check if Python is installed
$python = Get-Command python -ErrorAction SilentlyContinue

if ($python -eq $null) {
    Write-Host "Python not found. Installing Python..."
    # Download and install Python if not already installed
    $url = "https://www.python.org/ftp/python/3.9.9/python-3.9.9.exe"
    $installer = "python_installer.exe"
    Invoke-WebRequest -Uri $url -OutFile $installer
    Start-Process -FilePath $installer -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" -Wait
    Remove-Item -Path $installer
} else {
    Write-Host "Python is already installed."
}

# Check if pip is installed
$pip = Get-Command pip -ErrorAction SilentlyContinue

if ($pip -eq $null) {
    Write-Host "pip not found. Installing pip..."
    python -m ensurepip --upgrade
}

# Create virtual environment named 'converts'
Write-Host "Creating virtual environment 'converts'..."
python -m venv converts

# Activate virtual environment
Write-Host "Activating virtual environment..."
$activateScript = ".\converts\Scripts\Activate.ps1"
& $activateScript

# Install dependencies from requirements.txt
Write-Host "Installing dependencies from requirements.txt..."
pip install -r requirements.txt

Write-Host "Setup complete. Virtual environment 'converts' is ready."

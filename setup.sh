#!/bin/bash
# JS Scout Pro v10 - Automated Setup Script
# ========================================
# This script sets up the complete JS Scout Pro v10 with Burp automation

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print functions
print_header() {
    echo -e "${BLUE}"
    echo "███████╗███████╗    ███████╗ ██████╗ ██████╗ ██╗   ██╗████████╗"
    echo "██╔════╝██╔════╝    ██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝"
    echo "███████╗███████╗    ███████╗██║     ██║   ██║██║   ██║   ██║"
    echo "╚════██║╚════██║    ╚════██║██║     ██║   ██║██║   ██║   ██║"
    echo "███████║███████║    ███████║╚██████╗╚██████╔╝╚██████╔╝   ██║"
    echo "╚══════╝╚══════╝    ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝"
    echo "                                                              PRO v10"
    echo -e "${NC}"
    echo -e "${GREEN}🚀 JS Scout Pro v10 - Burp Automation Setup${NC}"
    echo -e "${YELLOW}============================================${NC}"
}

print_step() {
    echo -e "\n${BLUE}📦 $1${NC}"
    echo -e "${YELLOW}----------------------------------------${NC}"
}

print_success() {
    echo -e "\n${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "\n${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "\n${RED}❌ $1${NC}"
}

# Check if running as root (not recommended)
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_warning "Running as root is not recommended. Please run as a regular user."
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Check operating system
check_os() {
    print_step "Checking Operating System"
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        print_success "Linux detected"
        OS="linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        print_success "macOS detected"
        OS="macos"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
        print_success "Windows detected"
        OS="windows"
    else
        print_error "Unsupported operating system: $OSTYPE"
        exit 1
    fi
}

# Check Python installation
check_python() {
    print_step "Checking Python Installation"
    
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        print_success "Python3 found: $PYTHON_VERSION"
        
        # Check if version is 3.8 or higher
        if python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"; then
            print_success "Python version is compatible"
        else
            print_error "Python 3.8 or higher is required"
            exit 1
        fi
    else
        print_error "Python3 is not installed. Please install Python 3.8 or higher."
        exit 1
    fi
}

# Install system dependencies
install_system_deps() {
    print_step "Installing System Dependencies"
    
    case $OS in
        "linux")
            if command -v apt-get &> /dev/null; then
                echo "Detected Debian/Ubuntu-based system"
                sudo apt-get update
                sudo apt-get install -y python3-pip python3-venv git curl
            elif command -v yum &> /dev/null; then
                echo "Detected RHEL/CentOS-based system"
                sudo yum install -y python3-pip python3-venv git curl
            elif command -v dnf &> /dev/null; then
                echo "Detected Fedora-based system"
                sudo dnf install -y python3-pip python3-venv git curl
            else
                print_warning "Package manager not detected. Please install python3-pip, python3-venv, git, and curl manually."
            fi
            ;;
        "macos")
            if command -v brew &> /dev/null; then
                echo "Detected Homebrew"
                brew install python3 git curl
            else
                print_warning "Homebrew not found. Please install Python3, git, and curl manually."
            fi
            ;;
        "windows")
            print_warning "Please ensure Python3, git, and curl are installed on Windows."
            ;;
    esac
}

# Install browser drivers
install_browser_drivers() {
    print_step "Installing Browser Drivers"
    
    case $OS in
        "linux")
            if command -v apt-get &> /dev/null; then
                echo "Installing Chromium and ChromeDriver..."
                sudo apt-get install -y chromium chromium-driver
                print_success "Chromium and ChromeDriver installed"
            else
                print_warning "Please install Chromium or ChromeDriver manually for your Linux distribution."
            fi
            ;;
        "macos")
            if command -v brew &> /dev/null; then
                echo "Installing ChromeDriver via Homebrew..."
                brew install chromedriver
                print_success "ChromeDriver installed"
            else
                print_warning "Please install ChromeDriver manually."
            fi
            ;;
        "windows")
            print_warning "Please download and install ChromeDriver from: https://chromedriver.chromium.org/"
            ;;
    esac
}

# Create Python virtual environment
create_venv() {
    print_step "Creating Python Virtual Environment"
    
    if [ ! -d "venv" ]; then
        python3 -m venv venv
        print_success "Virtual environment created"
    else
        print_success "Virtual environment already exists"
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    print_success "Virtual environment activated"
}

# Upgrade pip
upgrade_pip() {
    print_step "Upgrading pip"
    pip install --upgrade pip
    print_success "pip upgraded"
}

# Install Python dependencies
install_python_deps() {
    print_step "Installing Python Dependencies"
    
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt
        print_success "Python dependencies installed"
    else
        print_error "requirements.txt not found"
        exit 1
    fi
}

# Check Burp Suite installation
check_burp() {
    print_step "Checking Burp Suite Installation"
    
    BURP_PATHS=(
        "/usr/bin/burpsuite"
        "/opt/burpsuite/burpsuite_pro.sh"
        "/Applications/Burp Suite Professional.app/Contents/MacOS/burpsuite"
        "C:\\Program Files\\BurpSuiteProfessional\\burpsuite_pro.exe"
        "$HOME/BurpSuite/burpsuite_pro.sh"
    )
    
    BURP_FOUND=false
    
    for path in "${BURP_PATHS[@]}"; do
        if [ -f "$path" ] || [ -x "$path" ]; then
            print_success "Burp Suite found at: $path"
            BURP_FOUND=true
            break
        fi
    done
    
    if [ "$BURP_FOUND" = false ]; then
        print_warning "Burp Suite not found in standard locations"
        echo -e "${YELLOW}Burp Suite Professional is required for automation features.${NC}"
        echo -e "${YELLOW}Please download from: https://portswigger.net/burp${NC}"
        echo -e "${YELLOW}After installation, you can specify the path with --burp-path${NC}"
        
        read -p "Continue setup without Burp Suite? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Create directories
create_directories() {
    print_step "Creating Directories"
    
    mkdir -p output
    mkdir -p logs
    mkdir -p reports
    mkdir -p config
    
    print_success "Directories created"
}

# Create configuration files
create_config() {
    print_step "Creating Configuration Files"
    
    # Create default config
    cat > config/default_config.json << EOF
{
    "scan_defaults": {
        "threads": 10,
        "timeout": 15,
        "pages": 200,
        "depth": 3
    },
    "burp_defaults": {
        "headless": true,
        "api_port": 1337,
        "proxy_port": 8080
    },
    "reporting": {
        "formats": ["json", "html", "csv", "txt"],
        "include_screenshots": true
    }
}
EOF
    
    print_success "Configuration files created"
}

# Test installation
test_installation() {
    print_step "Testing Installation"
    
    # Test Python imports
    python3 -c "
import sys
sys.path.insert(0, '.')

try:
    import requests
    print('✅ requests imported successfully')
except ImportError as e:
    print(f'❌ requests import failed: {e}')
    sys.exit(1)

try:
    import selenium
    print('✅ selenium imported successfully')
except ImportError as e:
    print(f'❌ selenium import failed: {e}')

try:
    from burp_automation import BurpAutomationEngine
    print('✅ burp_automation imported successfully')
except ImportError as e:
    print(f'❌ burp_automation import failed: {e}')

print('✅ All critical modules imported successfully')
"
    
    if [ $? -eq 0 ]; then
        print_success "Installation test passed"
    else
        print_error "Installation test failed"
        exit 1
    fi
}

# Create launcher scripts
create_launchers() {
    print_step "Creating Launcher Scripts"
    
    # Create main launcher
    cat > jsscout-pro-v10 << 'EOF'
#!/bin/bash
# JS Scout Pro v10 Launcher
# ========================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Activate virtual environment
if [ -d "venv" ]; then
    source venv/bin/activate
else
    echo "❌ Virtual environment not found. Please run setup.sh first."
    exit 1
fi

# Run the main scanner
python3 jsscout_pro_burp.py "$@"
EOF
    
    chmod +x jsscout-pro-v10
    
    # Create web UI launcher
    cat > jsscout-web-ui << 'EOF'
#!/bin/bash
# JS Scout Pro v10 Web UI Launcher
# =================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Activate virtual environment
if [ -d "venv" ]; then
    source venv/bin/activate
else
    echo "❌ Virtual environment not found. Please run setup.sh first."
    exit 1
fi

# Run the web server
python3 server.py
EOF
    
    chmod +x jsscout-web-ui
    
    print_success "Launcher scripts created"
}

# Print final instructions
print_final_instructions() {
    print_success "Setup completed successfully!"
    
    echo -e "\n${GREEN}🚀 QUICK START:${NC}"
    echo -e "${YELLOW}./jsscout-pro-v10 https://target.com${NC}"
    
    echo -e "\n${GREEN}🌐 WEB UI:${NC}"
    echo -e "${YELLOW}./jsscout-web-ui${NC}"
    echo -e "${YELLOW}Then open: http://localhost:7331${NC}"
    
    echo -e "\n${GREEN}📚 DOCUMENTATION:${NC}"
    echo -e "${YELLOW}See README_v10.md for detailed usage instructions${NC}"
    
    echo -e "\n${GREEN}📁 OUTPUT LOCATION:${NC}"
    echo -e "${YELLOW}./output/<target-domain>/${NC}"
    
    echo -e "\n${GREEN}⚙️  CONFIGURATION:${NC}"
    echo -e "${YELLOW}Edit config/default_config.json for default settings${NC}"
    
    if [ "$BURP_FOUND" = false ]; then
        echo -e "\n${YELLOW}⚠️  BURP SUITE:${NC}"
        echo -e "${YELLOW}Install Burp Suite Professional for full automation features${NC}"
        echo -e "${YELLOW}Download: https://portswigger.net/burp${NC}"
    fi
    
    echo -e "\n${GREEN}🎉 Happy hacking (responsibly)!${NC}"
}

# Main setup function
main() {
    print_header
    
    check_root
    check_os
    check_python
    install_system_deps
    install_browser_drivers
    create_venv
    upgrade_pip
    install_python_deps
    check_burp
    create_directories
    create_config
    test_installation
    create_launchers
    print_final_instructions
}

# Run main function
main "$@"

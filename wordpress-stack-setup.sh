#!/bin/bash
#
# WordPress Complete Stack Installation & Management Script
# Installs and configures: WordPress, MySQL, phpMyAdmin, Nginx/OpenLiteSpeed, PHP (multiple versions), and SSL (certbot)
# Author: Parham Fatemi
# Date: March 19, 2025
#
# Install with this command:
# curl -sSL https://raw.githubusercontent.com/parhamfa/wordpress-stack-installer/main/wordpress-stack-setup.sh -o wp-stack.sh
# chmod +x wp-stack.sh
# sudo ./wp-stack.sh
#

# Check if running with sudo
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run with sudo or as root."
    echo "Try: sudo bash $0"
    exit 1
fi

# ---- Color definitions for terminal UI ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ---- Global variables ----
SCRIPT_VERSION="1.1.0"
LOG_FILE="/var/log/wp-stack-installer.log"
NGINX_AVAILABLE="/etc/nginx/sites-available"
NGINX_ENABLED="/etc/nginx/sites-enabled"
OLS_CONF_DIR="/usr/local/lsws/conf"
OLS_VHOSTS_DIR="/usr/local/lsws/conf/vhosts"
OLS_ADMIN_PORT="7080"
OLS_ADMIN_PASSWORD=""
PHP_VERSION="8.2" # Default PHP version to install
AVAILABLE_PHP_VERSIONS=("7.4" "8.0" "8.1" "8.2" "8.3")
MYSQL_ROOT_PASSWORD=""
DOMAIN_NAME=""
WORDPRESS_DB_NAME=""
WORDPRESS_DB_USER=""
WORDPRESS_DB_PASSWORD=""
WP_INSTALL_PATH=""
WEB_SERVER="nginx" # Default web server

# ---- Function to log messages ----
log_message() {
    local message="$1"
    local level="${2:-INFO}"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

# ---- Function to display messages in terminal UI ----
print_message() {
    local message="$1"
    local type="${2:-info}"
    
    case "$type" in
        "info")
            echo -e "${BLUE}[INFO]${NC} $message"
            log_message "$message" "INFO"
            ;;
        "success")
            echo -e "${GREEN}[SUCCESS]${NC} $message"
            log_message "$message" "SUCCESS"
            ;;
        "warning")
            echo -e "${YELLOW}[WARNING]${NC} $message"
            log_message "$message" "WARNING"
            ;;
        "error")
            echo -e "${RED}[ERROR]${NC} $message"
            log_message "$message" "ERROR"
            ;;
        "header")
            echo -e "\n${BOLD}${PURPLE}$message${NC}\n"
            log_message "$message" "HEADER"
            ;;
        *)
            echo -e "$message"
            log_message "$message" "INFO"
            ;;
    esac
}

# ---- Function to show progress bar ----
show_progress() {
    local message="$1"
    local duration="${2:-5}"  # Default duration in seconds
    local chars="/-\|"
    local end=$((SECONDS+duration))
    
    echo -ne "${CYAN}$message${NC} "
    
    while [ $SECONDS -lt $end ]; do
        for (( i=0; i<${#chars}; i++ )); do
            echo -ne "\r${CYAN}$message${NC} ${chars:$i:1}"
            sleep 0.2
        done
    done
    echo -ne "\r${CYAN}$message${NC} ${GREEN}Done!${NC}\n"
}

# ---- Function to check if command exists ----
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# ---- Function to check if a package is installed ----
package_installed() {
    dpkg -l "$1" | grep -q "^ii" >/dev/null 2>&1
}

# ---- Function to check if user has sudo privileges ----
check_sudo() {
    if ! command_exists sudo; then
        print_message "sudo is not installed. Please install sudo and try again." "error"
        exit 1
    fi
    
    if ! sudo -n true 2>/dev/null; then
        print_message "This script requires sudo privileges. Please enter your password when prompted." "warning"
        sudo -v
        if [ $? -ne 0 ]; then
            print_message "Failed to obtain sudo privileges. Exiting." "error"
            exit 1
        fi
    fi
}

# ---- Function to check system requirements ----
check_system_requirements() {
    print_message "Checking system requirements..." "info"
    
    # Check if running on Debian/Ubuntu
    if ! command_exists apt-get; then
        print_message "This script is designed for Debian/Ubuntu systems. Exiting." "error"
        exit 1
    fi
    
    # Check disk space (at least 2GB free)
    local free_space=$(df -m / | awk 'NR==2 {print $4}')
    if [ "$free_space" -lt 2048 ]; then
        print_message "Not enough disk space. At least 2GB free space required." "error"
        exit 1
    fi
    
    # Check memory (at least 1GB recommended)
    local total_mem=$(free -m | awk '/^Mem:/{print $2}')
    if [ "$total_mem" -lt 1024 ]; then
        print_message "Low memory detected (${total_mem}MB). 1GB or more is recommended." "warning"
    fi
    
    print_message "System requirements check passed." "success"
    # Add a pause here to allow reading the system check results
    read -p "$(echo -e "${BLUE}Press Enter to continue...${NC} ")" pause
}

# ---- Function to get current installed components ----
get_installed_components() {
    local components=()
    
    # Check Nginx
    if command_exists nginx && systemctl is-active --quiet nginx; then
        components+=("nginx")
    fi
    
    # Check OpenLiteSpeed
    if [ -d "/usr/local/lsws" ] && systemctl is-active --quiet lsws 2>/dev/null; then
        components+=("openlitespeed")
    fi
    
    # Check MySQL/MariaDB
    if command_exists mysql && (systemctl is-active --quiet mysql || systemctl is-active --quiet mariadb); then
        components+=("mysql")
    fi
    
    # Check PHP - any version
    if command_exists php; then
        components+=("php")
    else
        # Also check for PHP-FPM or LSPHP installations that might not have the CLI symlink
        for version in "${AVAILABLE_PHP_VERSIONS[@]}"; do
            if [ -d "/etc/php/$version" ] || [ -d "/usr/local/lsws/lsphp$version" ]; then
                components+=("php")
                break
            fi
        done
    fi
    
    # Check phpMyAdmin
    if [ -d "/usr/share/phpmyadmin" ]; then
        components+=("phpmyadmin")
    fi
    
    # Check WordPress (This is a simple check, might need refinement)
    if [ -d "/var/www" ] && ([ -f "/var/www/html/wp-config.php" ] || find /var/www -name "wp-config.php" -type f 2>/dev/null | grep -q .); then
        components+=("wordpress")
    fi
    
    # Check certbot
    if command_exists certbot; then
        components+=("certbot")
    fi
    
    echo "${components[@]}"
}

# ---- Function to select web server ----
select_web_server() {
    print_message "Web Server Selection" "header"
    echo -e "1) ${BOLD}Nginx${NC} (Default, widely used, easy to configure)"
    echo -e "2) ${BOLD}OpenLiteSpeed${NC} (High performance, with built-in caching)"
    echo ""
    
    read -p "$(echo -e "${BLUE}Select web server [1-2, default: 1]:${NC} ")" server_choice
    
    case "$server_choice" in
        2)
            WEB_SERVER="openlitespeed"
            print_message "OpenLiteSpeed selected as web server." "success"
            ;;
        *)
            WEB_SERVER="nginx"
            print_message "Nginx selected as web server." "success"
            ;;
    esac
}

# ---- Function to select PHP version ----
select_php_version() {
    print_message "PHP Version Selection" "header"
    echo -e "Available PHP versions:"
    
    for i in "${!AVAILABLE_PHP_VERSIONS[@]}"; do
        local version="${AVAILABLE_PHP_VERSIONS[$i]}"
        if [ "$version" = "$PHP_VERSION" ]; then
            echo -e "$((i+1))) ${BOLD}PHP ${version}${NC} (Default)"
        else
            echo -e "$((i+1))) ${BOLD}PHP ${version}${NC}"
        fi
    done
    echo ""
    
    local max_option=${#AVAILABLE_PHP_VERSIONS[@]}
    read -p "$(echo -e "${BLUE}Select PHP version [1-${max_option}, default: PHP ${PHP_VERSION}]:${NC} ")" version_choice
    
    # Check if input is a number and in valid range
    if [[ "$version_choice" =~ ^[0-9]+$ && "$version_choice" -ge 1 && "$version_choice" -le "$max_option" ]]; then
        PHP_VERSION="${AVAILABLE_PHP_VERSIONS[$((version_choice-1))]}"
    fi
    
    print_message "PHP ${PHP_VERSION} selected." "success"
    
    # Check if PHP version is compatible with chosen web server
    if [ "$WEB_SERVER" = "openlitespeed" ]; then
        # For OpenLiteSpeed, check if the selected PHP version is available as LSPHP
        if ! apt-cache show "lsphp${PHP_VERSION}" &>/dev/null; then
            print_message "PHP ${PHP_VERSION} is not available for OpenLiteSpeed. Some versions may not be in default repositories." "warning"
            print_message "The script will try to install it anyway, but may fall back to PHP 8.0 if installation fails." "warning"
        fi
    else
        # For Nginx, check if the selected PHP version is available as PHP-FPM
        if ! apt-cache show "php${PHP_VERSION}-fpm" &>/dev/null; then
            print_message "PHP ${PHP_VERSION} is not available in the repositories. Adding PPA for additional PHP versions." "warning"
        fi
    fi
}

# ---- Function to create SSL configuration files ----
create_ssl_config_files() {
    # Create options-ssl-nginx.conf if it doesn't exist
    if [ ! -f "/etc/letsencrypt/options-ssl-nginx.conf" ]; then
        print_message "Creating SSL configuration files..." "info"
        
        sudo mkdir -p /etc/letsencrypt
        
        # Create modern SSL options file
        cat > /tmp/options-ssl-nginx.conf << 'EOL'
# This file contains important security parameters. If you modify this file manually, Certbot will be unable to automatically update it.

ssl_session_cache shared:le_nginx_SSL:10m;
ssl_session_timeout 1440m;
ssl_session_tickets off;

ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers off;

ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384";
EOL
        sudo mv /tmp/options-ssl-nginx.conf /etc/letsencrypt/options-ssl-nginx.conf
        
        # Create DH params (2048 bits)
        if [ ! -f "/etc/letsencrypt/ssl-dhparams.pem" ]; then
            print_message "Generating DH parameters (this may take a moment)..." "info"
            sudo openssl dhparam -out /etc/letsencrypt/ssl-dhparams.pem 2048
        fi
    fi
}

# ---- Function to update the system ----
update_system() {
    print_message "Updating system packages..." "header"
    sudo apt-get update
    if [ $? -ne 0 ]; then
        print_message "Failed to update system packages. Check your internet connection." "error"
        exit 1
    fi
    sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
    print_message "System packages updated successfully." "success"
}

# ---- Function to install Nginx ----
install_nginx() {
    if command_exists nginx && systemctl is-active --quiet nginx; then
        print_message "Nginx is already installed and running." "info"
        return 0
    fi
    
    print_message "Installing Nginx web server..." "header"
    sudo apt-get install -y nginx
    
    if [ $? -ne 0 ]; then
        print_message "Failed to install Nginx." "error"
        return 1
    fi
    
    # Enable and start Nginx
    sudo systemctl enable nginx
    sudo systemctl start nginx
    
    # Configure firewall if ufw is installed
    if command_exists ufw; then
        sudo ufw allow 'Nginx Full'
    fi
    
    print_message "Nginx installed and configured successfully." "success"
    return 0
}

# ---- Function to install OpenLiteSpeed ----
install_openlitespeed() {
    if [ -d "/usr/local/lsws" ] && systemctl is-active --quiet lsws 2>/dev/null; then
        print_message "OpenLiteSpeed is already installed and running." "info"
        return 0
    fi
    
    print_message "Installing OpenLiteSpeed web server..." "header"
    
    # Install prerequisites
    sudo apt-get install -y wget tar openssl libexpat1 libgeoip1 libpcre3 libxml2
    
    # Add OpenLiteSpeed repository
    wget -O - https://rpms.litespeedtech.com/debian/enable_lst_debian_repo.sh | sudo bash
    
    # Install OpenLiteSpeed
    sudo apt-get update
    sudo apt-get install -y openlitespeed
    
    if [ $? -ne 0 ]; then
        print_message "Failed to install OpenLiteSpeed." "error"
        return 1
    fi
    
    # Generate a secure admin password if not provided
    if [ -z "$OLS_ADMIN_PASSWORD" ]; then
        OLS_ADMIN_PASSWORD=$(openssl rand -base64 12)
        
        # Save the password to a secure file that only root can read
        echo "$OLS_ADMIN_PASSWORD" | sudo tee /root/.ols_admin_password > /dev/null
        sudo chmod 600 /root/.ols_admin_password
        
        print_message "----------------------------------------" "warning"
        print_message "IMPORTANT: OpenLiteSpeed ADMIN PASSWORD GENERATED" "warning"
        print_message "Password: $OLS_ADMIN_PASSWORD" "warning"
        print_message "This password has been saved to /root/.ols_admin_password" "warning"
        print_message "PLEASE WRITE THIS PASSWORD DOWN NOW!" "warning"
        print_message "WebAdmin URL: https://YOUR_SERVER_IP:$OLS_ADMIN_PORT/" "warning"
        print_message "Username: admin" "warning"
        print_message "----------------------------------------" "warning"
        
        # Make sure user acknowledges the password
        read -p "$(echo -e "${YELLOW}Have you saved this password? Type 'yes' to confirm:${NC} ")" confirm
        if [ "$confirm" != "yes" ]; then
            print_message "Please save the OpenLiteSpeed admin password before continuing." "error"
            exit 1
        fi
    fi
    
    # Set the admin password
    /usr/local/lsws/admin/misc/admpass.sh admin "$OLS_ADMIN_PASSWORD"
    
    # Configure OpenLiteSpeed to work with WordPress
    print_message "Configuring OpenLiteSpeed for WordPress..." "info"
    
    # Create OpenLiteSpeed directories for virtual hosts
    sudo mkdir -p "$OLS_VHOSTS_DIR"
    
    # Configure firewall if ufw is installed
    if command_exists ufw; then
        sudo ufw allow 80/tcp
        sudo ufw allow 443/tcp
        sudo ufw allow "$OLS_ADMIN_PORT"/tcp
    fi
    
    # Install LSCache for WordPress
    print_message "Installing LiteSpeed Cache for WordPress..." "info"
    mkdir -p /tmp/lscache-wp
    wget -O /tmp/lscache-wp/litespeed-cache.zip https://downloads.wordpress.org/plugin/litespeed-cache.zip
    
    print_message "OpenLiteSpeed installed and configured successfully." "success"
    print_message "WebAdmin URL: https://YOUR_SERVER_IP:$OLS_ADMIN_PORT/" "info"
    print_message "Username: admin" "info"
    print_message "Password: $OLS_ADMIN_PASSWORD" "info"
    return 0
}

# ---- Function to get MySQL root password ----
get_mysql_root_password() {
    # First, try to retrieve from the saved file
    if [ -f "/root/.mysql_root_password" ]; then
        MYSQL_ROOT_PASSWORD=$(sudo cat /root/.mysql_root_password)
        # Verify the password works
        if mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "SELECT 1" >/dev/null 2>&1; then
            return 0
        fi
    fi
    
    # If we got here, either the file doesn't exist or the password didn't work
    for attempt in {1..3}; do
        print_message "Enter MySQL root password (attempt $attempt/3):" "warning"
        read -sp "$(echo -e "${YELLOW}MySQL root password:${NC} ")" MYSQL_ROOT_PASSWORD
        echo ""
        
        # Verify the password works
        if mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "SELECT 1" >/dev/null 2>&1; then
            # Save the working password
            echo "$MYSQL_ROOT_PASSWORD" | sudo tee /root/.mysql_root_password > /dev/null
            sudo chmod 600 /root/.mysql_root_password
            print_message "Password verified and saved for future use." "success"
            return 0
        else
            print_message "Invalid password. Please try again." "error"
        fi
    done
    
    print_message "Failed to get valid MySQL root password after 3 attempts." "error"
    return 1
}

# ---- Function to install MySQL ----
install_mysql() {
    if command_exists mysql && (systemctl is-active --quiet mysql || systemctl is-active --quiet mariadb); then
        print_message "MySQL/MariaDB is already installed and running." "info"
        return 0
    fi
    
    print_message "Installing MySQL database server..." "header"
    
    # Generate a secure MySQL root password if not provided
    if [ -z "$MYSQL_ROOT_PASSWORD" ]; then
        MYSQL_ROOT_PASSWORD=$(openssl rand -base64 12)
        
        # Save the password to a secure file that only root can read
        echo "$MYSQL_ROOT_PASSWORD" | sudo tee /root/.mysql_root_password > /dev/null
        sudo chmod 600 /root/.mysql_root_password
        
        print_message "----------------------------------------" "warning"
        print_message "IMPORTANT: MySQL ROOT PASSWORD GENERATED" "warning"
        print_message "Password: $MYSQL_ROOT_PASSWORD" "warning"
        print_message "This password has been saved to /root/.mysql_root_password" "warning"
        print_message "PLEASE WRITE THIS PASSWORD DOWN NOW!" "warning"
        print_message "----------------------------------------" "warning"
        
        # Make sure user acknowledges the password
        read -p "$(echo -e "${YELLOW}Have you saved this password? Type 'yes' to confirm:${NC} ")" confirm
        if [ "$confirm" != "yes" ]; then
            print_message "Please save the MySQL root password before continuing." "error"
            exit 1
        fi
    fi
    
    # Set up root password for MySQL installation
    echo "mysql-server mysql-server/root_password password $MYSQL_ROOT_PASSWORD" | sudo debconf-set-selections
    echo "mysql-server mysql-server/root_password_again password $MYSQL_ROOT_PASSWORD" | sudo debconf-set-selections
    
    # Install MySQL
    sudo apt-get install -y mysql-server
    
    if [ $? -ne 0 ]; then
        print_message "Failed to install MySQL." "error"
        return 1
    fi
    
    # Enable and start MySQL
    sudo systemctl enable mysql
    sudo systemctl start mysql
    
    # Wait a moment for MySQL to fully start
    sleep 5
    
    # Verify MySQL is working with the password we set
    if ! mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "SELECT 1" >/dev/null 2>&1; then
        print_message "MySQL installed but the password setup may have failed." "warning"
        print_message "Let's reset the root password to make sure it works." "info"
        
        # For some MySQL installations (like Ubuntu), we might need to use the auth_socket plugin
        sudo mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '$MYSQL_ROOT_PASSWORD';" 2>/dev/null
        
        # If that fails, try an alternative method
        if [ $? -ne 0 ]; then
            print_message "Trying alternative password reset method..." "info"
            # Stop MySQL
            sudo systemctl stop mysql
            
            # Start MySQL in safe mode
            sudo mkdir -p /var/run/mysqld
            sudo chown mysql:mysql /var/run/mysqld
            sudo mysqld_safe --skip-grant-tables --skip-networking &
            sleep 5
            
            # Reset password
            sudo mysql -e "FLUSH PRIVILEGES; ALTER USER 'root'@'localhost' IDENTIFIED BY '$MYSQL_ROOT_PASSWORD';"
            
            # Stop safe mode MySQL and restart normal MySQL
            sudo pkill mysqld
            sleep 5
            sudo systemctl start mysql
            sleep 3
        fi
        
        # Verify password works now
        if mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "SELECT 1" >/dev/null 2>&1; then
            print_message "MySQL password reset successful." "success"
        else
            print_message "Failed to reset MySQL password. You may need to manually configure MySQL." "error"
        fi
    fi
    
    # Secure MySQL installation
    show_progress "Securing MySQL installation" 3
    
    # Run secure installation in a more automated way using the root password we just set
    mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "DELETE FROM mysql.user WHERE User='';" 2>/dev/null
    mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');" 2>/dev/null
    mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "DROP DATABASE IF EXISTS test;" 2>/dev/null
    mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';" 2>/dev/null
    mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "FLUSH PRIVILEGES;" 2>/dev/null
    
    print_message "MySQL installed and secured successfully." "success"
    return 0
}

# ---- Function to install PHP ----
install_php() {
    local php_version_installed=false
    
    # Check if any PHP version is already installed
    if command_exists php; then
        local current_version=$(php -v | head -n 1 | cut -d " " -f 2 | cut -d "." -f 1-2)
        
        # If the installed version matches the requested version
        if [ "$current_version" = "$PHP_VERSION" ]; then
            print_message "PHP $current_version is already installed." "info"
            return 0
        else
            print_message "PHP $current_version is installed, but PHP $PHP_VERSION was requested." "warning"
            read -p "$(echo -e "${YELLOW}Do you want to install PHP $PHP_VERSION alongside the existing version? (y/n):${NC} ")" install_another
            
            if [ "$install_another" != "y" ]; then
                print_message "Using existing PHP $current_version installation." "info"
                PHP_VERSION=$current_version
                return 0
            fi
            
            php_version_installed=true
        fi
    fi
    
    print_message "Installing PHP $PHP_VERSION and required extensions..." "header"
    
    # Add PPA for PHP (for Ubuntu)
    if command_exists add-apt-repository; then
        sudo add-apt-repository -y ppa:ondrej/php
        sudo apt-get update
    fi
    
    # Install PHP and required extensions
    if [ "$WEB_SERVER" = "openlitespeed" ]; then
        # For OpenLiteSpeed, we need to install LSPHP
        print_message "Installing LSPHP $PHP_VERSION for OpenLiteSpeed..." "info"
        
        # Try to install LSPHP with all required extensions
        if ! sudo apt-get install -y lsphp$PHP_VERSION lsphp$PHP_VERSION-common lsphp$PHP_VERSION-mysql \
            lsphp$PHP_VERSION-curl lsphp$PHP_VERSION-gd lsphp$PHP_VERSION-intl lsphp$PHP_VERSION-imap \
            lsphp$PHP_VERSION-mbstring lsphp$PHP_VERSION-opcache lsphp$PHP_VERSION-pdo lsphp$PHP_VERSION-soap \
            lsphp$PHP_VERSION-xml lsphp$PHP_VERSION-zip; then
            
            print_message "Failed to install LSPHP $PHP_VERSION. Falling back to LSPHP 8.0..." "warning"
            PHP_VERSION="8.0"
            
            # Try again with PHP 8.0
            sudo apt-get install -y lsphp$PHP_VERSION lsphp$PHP_VERSION-common lsphp$PHP_VERSION-mysql \
                lsphp$PHP_VERSION-curl lsphp$PHP_VERSION-gd lsphp$PHP_VERSION-intl lsphp$PHP_VERSION-imap \
                lsphp$PHP_VERSION-mbstring lsphp$PHP_VERSION-opcache lsphp$PHP_VERSION-pdo lsphp$PHP_VERSION-soap \
                lsphp$PHP_VERSION-xml lsphp$PHP_VERSION-zip
        fi
        
        # Create symlink for PHP CLI
        if [ ! -f "/usr/bin/php" ] || [ "$php_version_installed" = true ]; then
            sudo ln -sf /usr/local/lsws/lsphp$PHP_VERSION/bin/php /usr/bin/php
        fi
        
        # Configure PHP
        if [ -f "/usr/local/lsws/lsphp$PHP_VERSION/etc/php/$PHP_VERSION/litespeed/php.ini" ]; then
            sudo cp /usr/local/lsws/lsphp$PHP_VERSION/etc/php/$PHP_VERSION/litespeed/php.ini /usr/local/lsws/lsphp$PHP_VERSION/etc/php/$PHP_VERSION/litespeed/php.ini.bak
            sudo sed -i 's/upload_max_filesize = 2M/upload_max_filesize = 64M/' /usr/local/lsws/lsphp$PHP_VERSION/etc/php/$PHP_VERSION/litespeed/php.ini
            sudo sed -i 's/post_max_size = 8M/post_max_size = 64M/' /usr/local/lsws/lsphp$PHP_VERSION/etc/php/$PHP_VERSION/litespeed/php.ini
            sudo sed -i 's/memory_limit = 128M/memory_limit = 256M/' /usr/local/lsws/lsphp$PHP_VERSION/etc/php/$PHP_VERSION/litespeed/php.ini
            sudo sed -i 's/max_execution_time = 30/max_execution_time = 300/' /usr/local/lsws/lsphp$PHP_VERSION/etc/php/$PHP_VERSION/litespeed/php.ini
        else
            print_message "PHP INI file not found at expected location. PHP settings will use defaults." "warning"
        fi
        
        # Restart OpenLiteSpeed
        sudo systemctl restart lsws
        
    else
        # For Nginx, we use PHP-FPM
        print_message "Installing PHP-FPM $PHP_VERSION for Nginx..." "info"
        
        # Try to install PHP-FPM with all required extensions
        if ! sudo apt-get install -y php$PHP_VERSION php$PHP_VERSION-fpm php$PHP_VERSION-mysql \
            php$PHP_VERSION-curl php$PHP_VERSION-gd php$PHP_VERSION-mbstring php$PHP_VERSION-xml \
            php$PHP_VERSION-xmlrpc php$PHP_VERSION-zip php$PHP_VERSION-intl php$PHP_VERSION-soap; then
            
            print_message "Failed to install PHP-FPM $PHP_VERSION. Falling back to PHP 8.0..." "warning"
            PHP_VERSION="8.0"
            
            # Try again with PHP 8.0
            sudo apt-get install -y php$PHP_VERSION php$PHP_VERSION-fpm php$PHP_VERSION-mysql \
                php$PHP_VERSION-curl php$PHP_VERSION-gd php$PHP_VERSION-mbstring php$PHP_VERSION-xml \
                php$PHP_VERSION-xmlrpc php$PHP_VERSION-zip php$PHP_VERSION-intl php$PHP_VERSION-soap
        fi
        
        # Configure PHP
        if [ -f "/etc/php/$PHP_VERSION/fpm/php.ini" ]; then
            sudo cp /etc/php/$PHP_VERSION/fpm/php.ini /etc/php/$PHP_VERSION/fpm/php.ini.bak
            sudo sed -i 's/upload_max_filesize = 2M/upload_max_filesize = 64M/' /etc/php/$PHP_VERSION/fpm/php.ini
            sudo sed -i 's/post_max_size = 8M/post_max_size = 64M/' /etc/php/$PHP_VERSION/fpm/php.ini
            sudo sed -i 's/memory_limit = 128M/memory_limit = 256M/' /etc/php/$PHP_VERSION/fpm/php.ini
            sudo sed -i 's/max_execution_time = 30/max_execution_time = 300/' /etc/php/$PHP_VERSION/fpm/php.ini
        else
            print_message "PHP INI file not found at expected location. PHP settings will use defaults." "warning"
        fi
        
        # Restart PHP-FPM
        sudo systemctl restart php$PHP_VERSION-fpm
    fi
    
    if [ $? -ne 0 ]; then
        print_message "There were some issues during PHP installation." "warning"
        print_message "Please check error messages above and consider manually installing any missing extensions." "info"
    else
        print_message "PHP $PHP_VERSION installed and configured successfully." "success"
    fi
    
    # Provide information about installed PHP version
    if command_exists php; then
        local installed_version=$(php -v | head -n 1)
        print_message "Installed PHP version: $installed_version" "info"
    fi
    
    return 0
}

# ---- Function to install phpMyAdmin ----
install_phpmyadmin() {
    if [ -d "/usr/share/phpmyadmin" ]; then
        print_message "phpMyAdmin is already installed." "info"
        return 0
    fi
    
    print_message "Installing phpMyAdmin..." "header"
    
    # Set up default selections for phpMyAdmin installation
    echo "phpmyadmin phpmyadmin/dbconfig-install boolean true" | sudo debconf-set-selections
    echo "phpmyadmin phpmyadmin/app-password-confirm password $MYSQL_ROOT_PASSWORD" | sudo debconf-set-selections
    echo "phpmyadmin phpmyadmin/mysql/admin-pass password $MYSQL_ROOT_PASSWORD" | sudo debconf-set-selections
    echo "phpmyadmin phpmyadmin/mysql/app-pass password $MYSQL_ROOT_PASSWORD" | sudo debconf-set-selections
    
    # For Nginx, we need to set the reconfigure-webserver
    if [ "$WEB_SERVER" = "nginx" ]; then
        echo "phpmyadmin phpmyadmin/reconfigure-webserver multiselect nginx" | sudo debconf-set-selections
    else
        echo "phpmyadmin phpmyadmin/reconfigure-webserver multiselect none" | sudo debconf-set-selections
    fi
    
    # Install phpMyAdmin
    sudo apt-get install -y phpmyadmin
    
    if [ $? -ne 0 ]; then
        print_message "Failed to install phpMyAdmin." "error"
        return 1
    fi
    
    # Configure web server for phpMyAdmin
    if [ "$WEB_SERVER" = "nginx" ]; then
        # Create Nginx configuration for phpMyAdmin
        if [ ! -f "$NGINX_AVAILABLE/phpmyadmin.conf" ]; then
            cat > /tmp/phpmyadmin.conf << EOL
server {
    listen 80;
    server_name pma.${DOMAIN_NAME};
    root /usr/share/phpmyadmin;
    index index.php index.html index.htm;

    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php$PHP_VERSION-fpm.sock;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
    }

    location ~ /\.ht {
        deny all;
    }
}
EOL
            sudo mv /tmp/phpmyadmin.conf "$NGINX_AVAILABLE/phpmyadmin.conf"
            sudo ln -s "$NGINX_AVAILABLE/phpmyadmin.conf" "$NGINX_ENABLED/phpmyadmin.conf"
            sudo systemctl restart nginx
        fi
    elif [ "$WEB_SERVER" = "openlitespeed" ]; then
        # Create an OpenLiteSpeed virtual host for phpMyAdmin
        # First, create the virtual host config directory
        sudo mkdir -p "$OLS_VHOSTS_DIR/phpmyadmin"
        
        # Create the virtual host configuration
        cat > /tmp/phpmyadmin_vhost.conf << EOL
docRoot                   /usr/share/phpmyadmin
vhDomain                  pma.${DOMAIN_NAME}
adminEmails               admin@${DOMAIN_NAME}
enableGzip                1
enableIpGeo               0

rewrite  {
  enable                  1
  autoLoadHtaccess        1
}

context / {
  location                /usr/share/phpmyadmin
  allowBrowse             1
  
  rewrite  {
    enable                0
  }
  
  addDefaultCharset       off
  
  phpIniOverride  {
    php_admin_value upload_max_filesize 64M
    php_admin_value post_max_size 64M
    php_admin_value memory_limit 256M
    php_admin_value max_execution_time 300
  }
}

context /.well-known/ {
  location                ${VH_ROOT}/.well-known/
  allowBrowse             1
}

context /phpmyadmin {
  location                /usr/share/phpmyadmin
  allowBrowse             1
  
  phpIniOverride  {
    php_admin_value upload_max_filesize 64M
    php_admin_value post_max_size 64M
    php_admin_value memory_limit 256M
    php_admin_value max_execution_time 300
  }
}

EOL
        sudo mv /tmp/phpmyadmin_vhost.conf "$OLS_VHOSTS_DIR/phpmyadmin/vhconf.conf"
        
        # Add the virtual host to the main configuration
        # Create temporary file with new listener
        if ! grep -q "map pma.${DOMAIN_NAME}" "$OLS_CONF_DIR/httpd_config.conf"; then
            # Add mapping to listeners
            sudo sed -i "/listener HTTP/a \  map pma.${DOMAIN_NAME} phpmyadmin" "$OLS_CONF_DIR/httpd_config.conf"
            
            # Add virtual host entry if it doesn't exist
            if ! grep -q "virtualHost phpmyadmin" "$OLS_CONF_DIR/httpd_config.conf"; then
                echo "
virtualHost phpmyadmin {
  vhRoot                  /usr/share/phpmyadmin
  configFile              $OLS_VHOSTS_DIR/phpmyadmin/vhconf.conf
  allowSymbolLink         1
  enableScript            1
  restrained              1
  setUIDMode              0
}" | sudo tee -a "$OLS_CONF_DIR/httpd_config.conf" > /dev/null
            fi
            
            # Restart OpenLiteSpeed
            sudo systemctl restart lsws
        fi
    fi
    
    print_message "phpMyAdmin installed successfully." "success"
    print_message "You can access phpMyAdmin at http://pma.${DOMAIN_NAME} once DNS is configured." "info"
    return 0
}

# ---- Function to install Certbot for SSL ----
install_certbot() {
    if command_exists certbot; then
        print_message "Certbot is already installed." "info"
        return 0
    fi
    
    print_message "Installing Certbot for SSL certificates..." "header"
    
    # Install certbot and plugins based on web server
    if [ "$WEB_SERVER" = "nginx" ]; then
        sudo apt-get install -y certbot python3-certbot-nginx
    elif [ "$WEB_SERVER" = "openlitespeed" ]; then
        sudo apt-get install -y certbot
    fi
    
    if [ $? -ne 0 ]; then
        print_message "Failed to install Certbot." "error"
        return 1
    fi
    
    # Create SSL configuration files for manual usage
    create_ssl_config_files
    
    print_message "Certbot installed successfully." "success"
    return 0
}

# ---- Function to set up WordPress ----
install_wordpress() {
    local site_path="$1"
    local db_name="$2"
    local db_user="$3"
    local db_password="$4"
    local site_domain="$5"
    local installation_success=true
    
    print_message "Setting up WordPress at $site_path for $site_domain..." "header"
    
    # Create site directory if it doesn't exist
    if [ ! -d "$site_path" ]; then
        sudo mkdir -p "$site_path"
    fi
    
    # Download latest WordPress
    wget -q -O /tmp/wordpress.tar.gz https://wordpress.org/latest.tar.gz
    
    if [ $? -ne 0 ]; then
        print_message "Failed to download WordPress. Please check your internet connection." "error"
        return 1
    fi
    
    # Extract WordPress to the site directory
    sudo tar -xzf /tmp/wordpress.tar.gz -C /tmp
    sudo cp -rf /tmp/wordpress/* "$site_path"
    sudo rm -rf /tmp/wordpress.tar.gz /tmp/wordpress
    
    if [ $? -ne 0 ]; then
        print_message "Failed to extract WordPress files." "error"
        installation_success=false
        return 1
    fi
    
    # Set proper ownership and permissions
    sudo chown -R www-data:www-data "$site_path"
    sudo chmod -R 755 "$site_path"
    
    # Create WordPress database
    show_progress "Creating WordPress database and user" 2
    
    # Get MySQL root password
    if ! get_mysql_root_password; then
        print_message "Cannot proceed without valid MySQL credentials." "error"
        installation_success=false
        return 1
    fi
    
    # Create database and user with proper authentication
    if mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "CREATE DATABASE IF NOT EXISTS \`$db_name\`;" 2>/dev/null; then
        mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "CREATE USER IF NOT EXISTS '$db_user'@'localhost' IDENTIFIED BY '$db_password';"
        mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "GRANT ALL PRIVILEGES ON \`$db_name\`.* TO '$db_user'@'localhost';"
        mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e "FLUSH PRIVILEGES;"
        print_message "Database and user created successfully." "success"
    else
        print_message "Failed to create database. Please check your MySQL credentials." "error"
        installation_success=false
        return 1
    fi
    
    # Create wp-config.php
    cat > /tmp/wp-config.php << EOL
<?php
/**
 * WordPress Configuration File
 */

// ** Database settings ** //
define( 'DB_NAME', '$db_name' );
define( 'DB_USER', '$db_user' );
define( 'DB_PASSWORD', '$db_password' );
define( 'DB_HOST', 'localhost' );
define( 'DB_CHARSET', 'utf8' );
define( 'DB_COLLATE', '' );

EOL
    
    # Get salts from the WordPress API
    wget -q -O - https://api.wordpress.org/secret-key/1.1/salt/ >> /tmp/wp-config.php
    
    cat >> /tmp/wp-config.php << EOL

\$table_prefix = 'wp_';

define( 'WP_DEBUG', false );
define( 'SCRIPT_DEBUG', false );
define( 'WP_ENVIRONMENT_TYPE', 'production' );

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
    define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
EOL
    
    sudo mv /tmp/wp-config.php "$site_path/wp-config.php"
    sudo chown www-data:www-data "$site_path/wp-config.php"
    sudo chmod 640 "$site_path/wp-config.php"
    
    # Create web server configuration based on selected web server
    if [ "$WEB_SERVER" = "nginx" ]; then
        # Create Nginx site configuration
        cat > /tmp/wordpress.conf << EOL
server {
    listen 80;
    server_name $site_domain;
    root $site_path;
    
    index index.php index.html index.htm;
    
    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }
    
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php$PHP_VERSION-fpm.sock;
    }
    
    location ~ /\.ht {
        deny all;
    }
    
    location = /favicon.ico {
        log_not_found off;
        access_log off;
    }
    
    location = /robots.txt {
        allow all;
        log_not_found off;
        access_log off;
    }
    
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
        expires max;
        log_not_found off;
    }
}
EOL
        sudo mv /tmp/wordpress.conf "$NGINX_AVAILABLE/$site_domain.conf"
        sudo ln -sf "$NGINX_AVAILABLE/$site_domain.conf" "$NGINX_ENABLED/$site_domain.conf"
        
        # Restart Nginx
        sudo systemctl restart nginx
        
    elif [ "$WEB_SERVER" = "openlitespeed" ]; then
        # Create OpenLiteSpeed virtual host directory and configuration
        sudo mkdir -p "$OLS_VHOSTS_DIR/$site_domain"
        
        # Create the virtual host configuration
        cat > /tmp/wordpress_vhost.conf << EOL
docRoot                   $site_path
vhDomain                  $site_domain
adminEmails               admin@$site_domain
enableGzip                1
enableIpGeo               0

index  {
  useServer               0
  indexFiles              index.php, index.html
}

scripthandler  {
  add                     lsapi:lsphp$PHP_VERSION php
}

extprocessor lsphp$PHP_VERSION {
  type                    lsapi
  address                 UDS://tmp/lshttpd/lsphp$PHP_VERSION.sock
  maxConns                35
  env                     PHP_LSAPI_CHILDREN=35
  initTimeout             60
  retryTimeout            0
  persistConn             1
  respBuffer              0
  autoStart               1
  path                    /usr/local/lsws/lsphp$PHP_VERSION/bin/lsphp
  extUser                 www-data
  extGroup                www-data
  memSoftLimit            2047M
  memHardLimit            2047M
  procSoftLimit           400
  procHardLimit           500
}

phpIniOverride  {
  php_admin_value upload_max_filesize 64M
  php_admin_value post_max_size 64M
  php_admin_value memory_limit 256M
  php_admin_value max_execution_time 300
}

rewrite  {
  enable                  1
  autoLoadHtaccess        1
  rules                   <<<END_RULES
RewriteEngine On
RewriteBase /
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
  END_RULES
}

context / {
  location                $site_path
  allowBrowse             1
  
  rewrite  {
    enable                0
  }
}

context /.well-known/ {
  location                ${VH_ROOT}/.well-known/
  allowBrowse             1
}

context /wp-admin/ {
  location                $site_path/wp-admin/
  allowBrowse             1
  
  phpIniOverride  {
    php_admin_value upload_max_filesize 128M
    php_admin_value post_max_size 128M
    php_admin_value memory_limit 256M
    php_admin_value max_execution_time 600
  }
}
EOL
        sudo mv /tmp/wordpress_vhost.conf "$OLS_VHOSTS_DIR/$site_domain/vhconf.conf"
        
        # Add the virtual host to the main configuration
        if ! grep -q "map $site_domain" "$OLS_CONF_DIR/httpd_config.conf"; then
            # Add mapping to listeners
            sudo sed -i "/listener HTTP/a \  map $site_domain $site_domain" "$OLS_CONF_DIR/httpd_config.conf"
            
            # Add virtual host entry
            echo "
virtualHost $site_domain {
  vhRoot                  $site_path
  configFile              $OLS_VHOSTS_DIR/$site_domain/vhconf.conf
  allowSymbolLink         1
  enableScript            1
  restrained              1
  setUIDMode              0
}" | sudo tee -a "$OLS_CONF_DIR/httpd_config.conf" > /dev/null
            
            # Restart OpenLiteSpeed
            sudo systemctl restart lsws
        fi
        
        # Install LiteSpeed Cache for WordPress if available
        if [ -f "/tmp/lscache-wp/litespeed-cache.zip" ]; then
            sudo mkdir -p "$site_path/wp-content/plugins"
            sudo unzip -q -o /tmp/lscache-wp/litespeed-cache.zip -d "$site_path/wp-content/plugins/"
            sudo chown -R www-data:www-data "$site_path/wp-content"
            print_message "LiteSpeed Cache for WordPress installed." "success"
        fi
    fi
    
    if [ "$installation_success" = true ]; then
        print_message "WordPress installed successfully at $site_path" "success"
        print_message "You can access your WordPress site at: http://$site_domain" "info"
        print_message "Complete the WordPress installation by visiting this URL in your browser." "info"
        return 0
    else
        print_message "WordPress installation encountered errors. Please check the logs." "error"
        return 1
    fi
}

# ---- Function to configure SSL for a site ----
configure_ssl() {
    local domain="$1"
    local cert_type="standard"
    
    if ! command_exists certbot; then
        print_message "Certbot is not installed. Installing now..." "warning"
        install_certbot
    fi
    
    print_message "Configuring SSL for $domain..." "header"
    
    # Ask about certificate type
    print_message "Certificate types:" "info"
    print_message "1) Standard (only covers $domain)" "info"
    print_message "2) Wildcard (covers *.$domain - all subdomains)" "info"
    read -p "$(echo -e "${BLUE}Select certificate type [1-2]:${NC} ")" cert_choice
    
    if [ "$cert_choice" = "2" ]; then
        cert_type="wildcard"
    fi
    
    # Check if the site is accessible
    print_message "Before we get SSL, please make sure DNS for $domain is properly configured." "warning"
    print_message "The domain should be pointing to this server's IP address." "warning"
    
    read -p "$(echo -e "${YELLOW}Proceed with SSL configuration? (y/n):${NC} ")" confirm
    if [ "$confirm" != "y" ]; then
        print_message "SSL configuration aborted." "warning"
        return 1
    fi
    
    if [ "$cert_type" = "wildcard" ]; then
        print_message "Requesting wildcard certificate for *.$domain" "info"
        print_message "NOTE: Wildcard certificates require DNS validation." "warning"
        print_message "You will need to add a TXT record to your DNS configuration." "warning"
        print_message "Follow the instructions provided by Certbot." "warning"
        
        # Run certbot with DNS challenge for wildcard cert
        sudo certbot --manual --preferred-challenges dns certonly -d "$domain" -d "*.$domain" --agree-tos --email "admin@$domain"
        
        if [ $? -ne 0 ]; then
            print_message "Failed to obtain wildcard certificate. Check your DNS configuration." "error"
            return 1
        fi
        
        # Create SSL configuration files if they don't exist
        create_ssl_config_files
        
        # Configure web server to use the certificate
        if [ "$WEB_SERVER" = "nginx" ]; then
            print_message "Configuring Nginx to use the wildcard certificate..." "info"
            for conf in "$NGINX_AVAILABLE"/*.conf; do
                if grep -q "server_name.*$domain" "$conf"; then
                    # Create a backup of the original file
                    sudo cp "$conf" "${conf}.bak"
                    
                    # Extract site path from the configuration file
                    local site_path=$(grep "root" "$conf" | head -1 | awk '{print $2}' | sed 's/;$//')
                    
                    # Replace the entire server block with our ssl-enabled version
                    cat > /tmp/ssl-server-block.conf << EOL
server {
    listen 80;
    server_name $domain www.$domain *.$domain;
    
    # Redirect HTTP to HTTPS
    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name $domain www.$domain *.$domain;
    
    ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;
    
    # SSL settings
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305";
    
    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    
    # Domain root
    root $site_path;
    index index.php index.html index.htm;
    
    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }
    
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php$PHP_VERSION-fpm.sock;
    }
    
    location ~ /\.ht {
        deny all;
    }
    
    location = /favicon.ico {
        log_not_found off;
        access_log off;
    }
    
    location = /robots.txt {
        allow all;
        log_not_found off;
        access_log off;
    }
    
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
        expires max;
        log_not_found off;
    }
}
EOL
                    sudo mv /tmp/ssl-server-block.conf "$conf"
                    print_message "Updated configuration for $conf" "success"
                fi
            done
            
            # Restart Nginx
            sudo systemctl restart nginx
            
        elif [ "$WEB_SERVER" = "openlitespeed" ]; then
            print_message "Configuring OpenLiteSpeed to use the wildcard certificate..." "info"
            
            # Add SSL to virtual host configuration
            for vh_dir in "$OLS_VHOSTS_DIR"/*; do
                if [ -d "$vh_dir" ] && [ -f "$vh_dir/vhconf.conf" ]; then
                    local vh_name=$(basename "$vh_dir")
                    
                    if grep -q "vhDomain.*$domain" "$vh_dir/vhconf.conf"; then
                        # Add SSL configuration to the virtual host
                        if ! grep -q "vhssl" "$vh_dir/vhconf.conf"; then
                            cat >> "$vh_dir/vhconf.conf" << EOL

vhssl  {
  keyFile                 /etc/letsencrypt/live/$domain/privkey.pem
  certFile                /etc/letsencrypt/live/$domain/fullchain.pem
  certChain               1
  sslProtocol             24
  renegProtection         1
  sslSessionCache         1
  sslSessionTickets       0
  enableECDHE             1
  enableDHE               1
  ciphers                 EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH
  enableSpdy              15
  ocspStapling            1
}
EOL
                            print_message "Added SSL configuration to $vh_name" "success"
                        fi
                        
                        # Add HTTP to HTTPS redirection
                        if ! grep -q "RewriteCond %{HTTPS} off" "$vh_dir/vhconf.conf"; then
                            # Add rewrite rules for HTTP to HTTPS redirection
                            sed -i "/rewrite  {/a \  rules                   <<<END_RULES\nRewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule (.*) https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]\n  END_RULES" "$vh_dir/vhconf.conf"
                            print_message "Added HTTP to HTTPS redirection for $vh_name" "success"
                        fi
                    fi
                fi
            done
            
            # Update listeners to enable SSL
            if ! grep -q "listener HTTPS" "$OLS_CONF_DIR/httpd_config.conf"; then
                # Add HTTPS listener
                cat >> "$OLS_CONF_DIR/httpd_config.conf" << EOL

listener HTTPS {
  address                 *:443
  secure                  1
  keyFile                 /etc/letsencrypt/live/$domain/privkey.pem
  certFile                /etc/letsencrypt/live/$domain/fullchain.pem
  certChain               1
  sslProtocol             24
  renegProtection         1
  sslSessionCache         1
  sslSessionTickets       0
  enableECDHE             1
  enableDHE               1
  ciphers                 EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH
  enableSpdy              15
  ocspStapling            1
  map                     $domain $domain
  map                     *.$domain $domain
}
EOL
                print_message "Added HTTPS listener for OpenLiteSpeed" "success"
            else
                # Add domain mapping to existing HTTPS listener
                sudo sed -i "/listener HTTPS/,/}/s/}/  map                     $domain $domain\n  map                     *.$domain $domain\n}/" "$OLS_CONF_DIR/httpd_config.conf"
                print_message "Added domain mapping to HTTPS listener" "success"
            fi
            
            # Restart OpenLiteSpeed
            sudo systemctl restart lsws
        fi
        
    else
        # Standard certificate
        if [ "$WEB_SERVER" = "nginx" ]; then
            # Use Nginx plugin
            sudo certbot --nginx -d "$domain" --non-interactive --agree-tos --email "admin@$domain"
            
            if [ $? -ne 0 ]; then
                print_message "Failed to obtain SSL certificate. Check your domain configuration." "error"
                return 1
            fi
            
        elif [ "$WEB_SERVER" = "openlitespeed" ]; then
            # Use webroot plugin
            local site_path=""
            
            # Find the site path from OpenLiteSpeed configs
            for vh_dir in "$OLS_VHOSTS_DIR"/*; do
                if [ -d "$vh_dir" ] && [ -f "$vh_dir/vhconf.conf" ]; then
                    if grep -q "vhDomain.*$domain" "$vh_dir/vhconf.conf"; then
                        site_path=$(grep "docRoot" "$vh_dir/vhconf.conf" | head -1 | awk '{print $2}')
                        break
                    fi
                fi
            done
            
            if [ -z "$site_path" ]; then
                print_message "Could not find site path for $domain. SSL configuration aborted." "error"
                return 1
            fi
            
            # Get the certificate using webroot plugin
            sudo certbot certonly --webroot --webroot-path="$site_path" -d "$domain" --agree-tos --email "admin@$domain" --non-interactive
            
            if [ $? -ne 0 ]; then
                print_message "Failed to obtain SSL certificate. Check your domain configuration." "error"
                return 1
            fi
            
            # Add SSL to virtual host configuration
            for vh_dir in "$OLS_VHOSTS_DIR"/*; do
                if [ -d "$vh_dir" ] && [ -f "$vh_dir/vhconf.conf" ]; then
                    if grep -q "vhDomain.*$domain" "$vh_dir/vhconf.conf"; then
                        # Add SSL configuration to the virtual host
                        if ! grep -q "vhssl" "$vh_dir/vhconf.conf"; then
                            cat >> "$vh_dir/vhconf.conf" << EOL

vhssl  {
  keyFile                 /etc/letsencrypt/live/$domain/privkey.pem
  certFile                /etc/letsencrypt/live/$domain/fullchain.pem
  certChain               1
  sslProtocol             24
  renegProtection         1
  sslSessionCache         1
  sslSessionTickets       0
  enableECDHE             1
  enableDHE               1
  ciphers                 EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH
  enableSpdy              15
  ocspStapling            1
}
EOL
                            print_message "Added SSL configuration to virtual host" "success"
                        fi
                        
                        # Add HTTP to HTTPS redirection
                        if ! grep -q "RewriteCond %{HTTPS} off" "$vh_dir/vhconf.conf"; then
                            # Add rewrite rules for HTTP to HTTPS redirection
                            sed -i "/rewrite  {/a \  rules                   <<<END_RULES\nRewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule (.*) https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]\n  END_RULES" "$vh_dir/vhconf.conf"
                            print_message "Added HTTP to HTTPS redirection" "success"
                        fi
                    fi
                fi
            done
            
            # Update listeners to enable SSL
            if ! grep -q "listener HTTPS" "$OLS_CONF_DIR/httpd_config.conf"; then
                # Add HTTPS listener
                cat >> "$OLS_CONF_DIR/httpd_config.conf" << EOL

listener HTTPS {
  address                 *:443
  secure                  1
  keyFile                 /etc/letsencrypt/live/$domain/privkey.pem
  certFile                /etc/letsencrypt/live/$domain/fullchain.pem
  certChain               1
  sslProtocol             24
  renegProtection         1
  sslSessionCache         1
  sslSessionTickets       0
  enableECDHE             1
  enableDHE               1
  ciphers                 EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH
  enableSpdy              15
  ocspStapling            1
  map                     $domain $domain
}
EOL
                print_message "Added HTTPS listener for OpenLiteSpeed" "success"
            else
                # Add domain mapping to existing HTTPS listener
                sudo sed -i "/listener HTTPS/,/}/s/}/  map                     $domain $domain\n}/" "$OLS_CONF_DIR/httpd_config.conf"
                print_message "Added domain mapping to HTTPS listener" "success"
            fi
            
            # Restart OpenLiteSpeed
            sudo systemctl restart lsws
        fi
    fi
    
    print_message "SSL certificate obtained and configured successfully for $domain" "success"
    print_message "Your site is now accessible via HTTPS: https://$domain" "success"
    
    read -p "$(echo -e "${BLUE}Press Enter to continue...${NC} ")" pause
    
    return 0
}

# ---- Function to prompt for and collect site information ----
collect_site_info() {
    print_message "WordPress Site Setup" "header"
    
    # Domain name
    read -p "$(echo -e "${BLUE}Enter domain name (e.g., example.com or sub.example.com):${NC} ")" DOMAIN_NAME
    while [[ -z "$DOMAIN_NAME" || ! "$DOMAIN_NAME" =~ ^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$ ]]; do
        print_message "Invalid domain name format. Please enter a valid domain." "error"
        read -p "$(echo -e "${BLUE}Enter domain name (e.g., example.com or sub.example.com):${NC} ")" DOMAIN_NAME
    done
    
    # Installation path
    read -p "$(echo -e "${BLUE}Enter installation path [/var/www/${DOMAIN_NAME}]:${NC} ")" WP_INSTALL_PATH
    WP_INSTALL_PATH=${WP_INSTALL_PATH:-/var/www/${DOMAIN_NAME}}
    
    # Database name
    WORDPRESS_DB_NAME=$(echo ${DOMAIN_NAME} | sed 's/[^a-zA-Z0-9]/_/g')
    read -p "$(echo -e "${BLUE}Enter database name [${WORDPRESS_DB_NAME}]:${NC} ")" DB_NAME_INPUT
    WORDPRESS_DB_NAME=${DB_NAME_INPUT:-$WORDPRESS_DB_NAME}
    
    # Database user
    WORDPRESS_DB_USER=$(echo ${DOMAIN_NAME} | sed 's/[^a-zA-Z0-9]/_/g' | cut -c 1-12)
    read -p "$(echo -e "${BLUE}Enter database username [${WORDPRESS_DB_USER}]:${NC} ")" DB_USER_INPUT
    WORDPRESS_DB_USER=${DB_USER_INPUT:-$WORDPRESS_DB_USER}
    
    # Database password
    default_password=$(openssl rand -base64 12)
    read -p "$(echo -e "${BLUE}Enter database password [${default_password}]:${NC} ")" DB_PASSWORD_INPUT
    WORDPRESS_DB_PASSWORD=${DB_PASSWORD_INPUT:-$default_password}
    
    print_message "Site information collected successfully." "success"
    print_message "Domain: $DOMAIN_NAME" "info"
    print_message "Install Path: $WP_INSTALL_PATH" "info"
    print_message "Database Name: $WORDPRESS_DB_NAME" "info"
    print_message "Database User: $WORDPRESS_DB_USER" "info"
    
    # Confirm information
    read -p "$(echo -e "${YELLOW}Is this information correct? (y/n):${NC} ")" confirm
    if [ "$confirm" != "y" ]; then
        print_message "Site information discarded. Let's try again." "warning"
        collect_site_info
    fi
}

# ---- Function to display script banner ----
show_banner() {
    if [ "$1" != "nobreak" ]; then
        # Only clear the screen if explicitly told not to preserve output
        clear
    fi
    
    echo -e "${BOLD}${CYAN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                                                          ║"
    echo "║       WordPress Complete Stack Installer v$SCRIPT_VERSION       ║"
    echo "║                                                          ║"
    echo "║   WordPress + MySQL + phpMyAdmin + Web Server + PHP + SSL    ║"
    echo "║                                                          ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ---- Function to display menu ----
show_menu() {
    local installed_components=($(get_installed_components))
    local preserve_output="$1"
    
    if [ "$preserve_output" != "nobreak" ]; then
        # Only clear the screen if explicitly told not to preserve output
        show_banner
    fi
    
    print_message "System Status" "header"
    
    # Check Web Server
    if [[ " ${installed_components[@]} " =~ " nginx " ]]; then
        echo -e "- Web Server: ${GREEN}Nginx Installed${NC}"
        WEB_SERVER="nginx"
    elif [[ " ${installed_components[@]} " =~ " openlitespeed " ]]; then
        echo -e "- Web Server: ${GREEN}OpenLiteSpeed Installed${NC}"
        WEB_SERVER="openlitespeed"
    else
        echo -e "- Web Server: ${RED}Not Installed${NC}"
    fi
    
    # Check MySQL
    if [[ " ${installed_components[@]} " =~ " mysql " ]]; then
        echo -e "- MySQL Database: ${GREEN}Installed${NC}"
    else
        echo -e "- MySQL Database: ${RED}Not Installed${NC}"
    fi
    
    # Check PHP - Now show all installed PHP versions
    if [[ " ${installed_components[@]} " =~ " php " ]]; then
        # Get all installed PHP versions
        local php_versions=""
        for version in "${AVAILABLE_PHP_VERSIONS[@]}"; do
            if command_exists "php$version" || [ -d "/etc/php/$version" ] || [ -d "/usr/local/lsws/lsphp$version" ]; then
                if [ -z "$php_versions" ]; then
                    php_versions="$version"
                else
                    php_versions="$php_versions, $version"
                fi
            fi
        done
        
        # Get active PHP version
        local active_php_version=$(php -v | head -n 1 | cut -d " " -f 2 | cut -d "." -f 1-2)
        echo -e "- PHP: ${GREEN}Installed (Active: v$active_php_version, Available: $php_versions)${NC}"
        
        # Set the active PHP version as the current PHP_VERSION
        PHP_VERSION=$active_php_version
    else
        echo -e "- PHP: ${RED}Not Installed${NC}"
    fi
    
    # Check phpMyAdmin
    if [[ " ${installed_components[@]} " =~ " phpmyadmin " ]]; then
        echo -e "- phpMyAdmin: ${GREEN}Installed${NC}"
    else
        echo -e "- phpMyAdmin: ${RED}Not Installed${NC}"
    fi
    
    # Check WordPress
    if [[ " ${installed_components[@]} " =~ " wordpress " ]]; then
        # Find all WordPress installations
        local wp_installations=$(find /var/www -name "wp-config.php" -type f 2>/dev/null | wc -l)
        echo -e "- WordPress: ${GREEN}Installed ($wp_installations site(s))${NC}"
    else
        echo -e "- WordPress: ${RED}Not Installed${NC}"
    fi
    
    # Check Certbot
    if [[ " ${installed_components[@]} " =~ " certbot " ]]; then
        echo -e "- Certbot (SSL): ${GREEN}Installed${NC}"
    else
        echo -e "- Certbot (SSL): ${RED}Not Installed${NC}"
    fi
    
    echo ""
    print_message "Available Actions" "header"
    
    if [ ${#installed_components[@]} -lt 6 ]; then
        echo -e "1) ${BOLD}Install Complete Stack${NC}"
    else
        echo -e "1) ${BOLD}Reinstall/Update Stack Components${NC}"
    fi
    
    if ([[ " ${installed_components[@]} " =~ " nginx " ]] || [[ " ${installed_components[@]} " =~ " openlitespeed " ]]) && \
       [[ " ${installed_components[@]} " =~ " mysql " ]] && \
       [[ " ${installed_components[@]} " =~ " php " ]]; then
        echo -e "2) ${BOLD}Create New WordPress Site${NC}"
    else
        echo -e "2) ${BOLD}Create New WordPress Site${NC} ${YELLOW}(Requires complete stack)${NC}"
    fi
    
    if [[ " ${installed_components[@]} " =~ " certbot " ]]; then
        echo -e "3) ${BOLD}Configure SSL for a Site${NC}"
    else
        echo -e "3) ${BOLD}Configure SSL for a Site${NC} ${YELLOW}(Requires Certbot)${NC}"
    fi
    
    if [[ " ${installed_components[@]} " =~ " wordpress " ]]; then
        echo -e "4) ${BOLD}List Existing WordPress Sites${NC}"
    else
        echo -e "4) ${BOLD}List Existing WordPress Sites${NC} ${YELLOW}(No sites available)${NC}"
    fi
    
    echo -e "5) ${BOLD}System Information${NC}"
    echo -e "6) ${BOLD}Exit${NC}"
    echo ""
}

# ---- Function to list WordPress installations ----
list_wordpress_sites() {
    print_message "WordPress Sites on this Server" "header"
    
    # Create /var/www if it doesn't exist
    if [ ! -d "/var/www" ]; then
        print_message "Directory /var/www does not exist yet. No WordPress sites installed." "warning"
        return
    fi
    
    # Find all wp-config.php files
    local configs=$(find /var/www -name "wp-config.php" -type f 2>/dev/null)
    
    if [ -z "$configs" ]; then
        print_message "No WordPress installations found." "warning"
        return
    fi
    
    echo -e "${BOLD}ID  | Site Path                | Domain                 | Database${NC}"
    echo "----|--------------------------|------------------------|------------------"
    
    local counter=1
    while IFS= read -r config; do
        local site_path=$(dirname "$config")
        local db_name=$(grep DB_NAME "$config" | cut -d "'" -f 4)
        
        # Try to determine domain from web server configs
        local domain=""
        
        if [ "$WEB_SERVER" = "nginx" ]; then
            for conf in "$NGINX_AVAILABLE"/*.conf; do
                if grep -q "$site_path" "$conf"; then
                    domain=$(grep "server_name" "$conf" | head -1 | awk '{print $2}' | sed 's/;$//')
                    break
                fi
            done
        elif [ "$WEB_SERVER" = "openlitespeed" ]; then
            for vh_dir in "$OLS_VHOSTS_DIR"/*; do
                if [ -d "$vh_dir" ] && [ -f "$vh_dir/vhconf.conf" ]; then
                    if grep -q "$site_path" "$vh_dir/vhconf.conf"; then
                        domain=$(grep "vhDomain" "$vh_dir/vhconf.conf" | head -1 | awk '{print $2}')
                        break
                    fi
                fi
            done
        fi
        
        printf "%-4s| %-24s| %-24s| %s\n" "$counter" "$site_path" "${domain:-Unknown}" "${db_name:-Unknown}"
        ((counter++))
    done <<< "$configs"
    
    echo ""
}

# ---- Function to display system information ----
show_system_info() {
    print_message "System Information" "header"
    
    # OS Information
    echo -e "${BOLD}Operating System:${NC}"
    lsb_release -a 2>/dev/null || cat /etc/os-release
    echo ""
    
    # CPU Information
    echo -e "${BOLD}CPU Information:${NC}"
    grep "model name" /proc/cpuinfo | head -1
    echo "CPU Cores: $(grep -c processor /proc/cpuinfo)"
    echo ""
    
    # Memory Information
    echo -e "${BOLD}Memory Information:${NC}"
    free -h
    echo ""
    
    # Disk Information
    echo -e "${BOLD}Disk Usage:${NC}"
    df -h /
    echo ""
    
    # Web Server Information
    if command_exists nginx; then
        echo -e "${BOLD}Nginx Version:${NC}"
        nginx -v 2>&1
        echo ""
    fi
    
    if [ -f "/usr/local/lsws/bin/lshttpd" ]; then
        echo -e "${BOLD}OpenLiteSpeed Version:${NC}"
        /usr/local/lsws/bin/lshttpd -v 2>&1
        echo ""
    fi
    
    # PHP Information - Show all installed versions
    echo -e "${BOLD}PHP Versions:${NC}"
    if command_exists php; then
        echo -e "Active PHP version (CLI): $(php -v | head -1)"
    fi
    
    # Check for installed PHP-FPM versions
    echo -e "\nInstalled PHP-FPM versions:"
    for version in "${AVAILABLE_PHP_VERSIONS[@]}"; do
        if [ -d "/etc/php/$version/fpm" ]; then
            local status=$(systemctl is-active php$version-fpm 2>/dev/null)
            if [ "$status" = "active" ]; then
                echo -e "- PHP $version: ${GREEN}Installed and Active${NC}"
            else
                echo -e "- PHP $version: ${YELLOW}Installed but Inactive${NC}"
            fi
        fi
    done
    
    # Check for installed LSPHP versions
    if [ -d "/usr/local/lsws" ]; then
        echo -e "\nInstalled LSPHP versions for OpenLiteSpeed:"
        for version in "${AVAILABLE_PHP_VERSIONS[@]}"; do
            if [ -d "/usr/local/lsws/lsphp$version" ]; then
                echo -e "- LSPHP $version: ${GREEN}Installed${NC}"
            fi
        done
    fi
    echo ""
    
    # MySQL Information
    if command_exists mysql; then
        echo -e "${BOLD}MySQL Version:${NC}"
        mysql --version
        echo ""
    fi
    
    # Certbot Information
    if command_exists certbot; then
        echo -e "${BOLD}Certbot Version:${NC}"
        certbot --version
        echo ""
    fi
}

# ---- Function to install the complete stack ----
install_complete_stack() {
    print_message "Installing Complete WordPress Stack" "header"
    
    # Ask user to select web server
    select_web_server
    
    # Ask user to select PHP version
    select_php_version
    
    # Update system packages
    update_system
    
    # Install components
    if [ "$WEB_SERVER" = "nginx" ]; then
        install_nginx
    elif [ "$WEB_SERVER" = "openlitespeed" ]; then
        install_openlitespeed
    fi
    
    install_mysql
    install_php
    install_phpmyadmin
    install_certbot
    
    print_message "WordPress stack installation completed successfully!" "success"
    print_message "You can now create a new WordPress site." "info"
    
    read -p "$(echo -e "${BLUE}Press Enter to continue...${NC} ")" pause
}

# ---- Main function ----
main() {
    # Create log file if it doesn't exist
    if [ ! -f "$LOG_FILE" ]; then
        sudo touch "$LOG_FILE"
        sudo chmod 644 "$LOG_FILE"
    fi
    
    # Check for sudo privileges
    check_sudo
    
    # Check system requirements
    check_system_requirements
    
    # Show initial banner without clearing screen (first time only)
    show_banner "nobreak"
    
    while true; do
        # Show menu (will clear screen on subsequent iterations)
        if [ -n "$FIRST_RUN" ]; then
            show_menu
        else
            FIRST_RUN=1
            show_menu "nobreak" 
        fi
        
        read -p "$(echo -e "${BLUE}Enter your choice [1-6]:${NC} ")" choice
        
        case $choice in
            1)
                install_complete_stack
                ;;
            2)
                # Check if required components are installed
                local installed_components=($(get_installed_components))
                if ([[ " ${installed_components[@]} " =~ " nginx " ]] || [[ " ${installed_components[@]} " =~ " openlitespeed " ]]) && \
                   [[ " ${installed_components[@]} " =~ " mysql " ]] && \
                   [[ " ${installed_components[@]} " =~ " php " ]]; then
                    
                    # Determine which web server is installed
                    if [[ " ${installed_components[@]} " =~ " nginx " ]]; then
                        WEB_SERVER="nginx"
                    elif [[ " ${installed_components[@]} " =~ " openlitespeed " ]]; then
                        WEB_SERVER="openlitespeed"
                    fi
                    
                    # Get active PHP version
                    if command_exists php; then
                        PHP_VERSION=$(php -v | head -n 1 | cut -d " " -f 2 | cut -d "." -f 1-2)
                    fi
                    
                    # Allow user to select a different PHP version if they want
                    read -p "$(echo -e "${BLUE}Current PHP version is $PHP_VERSION. Do you want to use a different version? (y/n):${NC} ")" change_php
                    if [ "$change_php" = "y" ]; then
                        select_php_version
                    fi
                    
                    collect_site_info
                    # Install WordPress
                    if ! install_wordpress "$WP_INSTALL_PATH" "$WORDPRESS_DB_NAME" "$WORDPRESS_DB_USER" "$WORDPRESS_DB_PASSWORD" "$DOMAIN_NAME"; then
                        print_message "WordPress installation failed. Please check the log for details." "error"
                        read -p "$(echo -e "${BLUE}Press Enter to continue...${NC} ")" pause
                        continue
                    fi
                    
                    # Ask if they want to set up SSL
                    read -p "$(echo -e "${YELLOW}Would you like to set up SSL for this site now? (y/n):${NC} ")" ssl_choice
                    if [ "$ssl_choice" = "y" ]; then
                        configure_ssl "$DOMAIN_NAME"
                    else
                        print_message "You can set up SSL later by selecting option 3 from the main menu." "info"
                    fi
                    
                    print_message "WordPress site setup complete!" "header"
                    print_message "Website URL: http://$DOMAIN_NAME" "info"
                    print_message "Admin area: http://$DOMAIN_NAME/wp-admin/" "info"
                    print_message "Database name: $WORDPRESS_DB_NAME" "info"
                    print_message "Database user: $WORDPRESS_DB_USER" "info"
                    print_message "Database password: $WORDPRESS_DB_PASSWORD" "info"
                    
                    if [ "$WEB_SERVER" = "openlitespeed" ]; then
                        print_message "LiteSpeed Cache has been installed for better performance." "info"
                    fi
                    
                    read -p "$(echo -e "${BLUE}Press Enter to return to the main menu...${NC} ")" pause
                else
                    print_message "Complete stack not installed. Please install the complete stack first." "error"
                    read -p "$(echo -e "${BLUE}Press Enter to continue...${NC} ")" pause
                fi
                ;;
            3)
                # Set up SSL for a site
                local installed_components=($(get_installed_components))
                if [[ " ${installed_components[@]} " =~ " certbot " ]]; then
                    # List sites and ask which one to configure SSL for
                    list_wordpress_sites
                    
                    read -p "$(echo -e "${BLUE}Enter domain to configure SSL for:${NC} ")" ssl_domain
                    configure_ssl "$ssl_domain"
                else
                    print_message "Certbot not installed. Please install the complete stack first." "error"
                    read -p "$(echo -e "${BLUE}Press Enter to continue...${NC} ")" pause
                fi
                ;;
            4)
                # List WordPress sites
                list_wordpress_sites
                read -p "$(echo -e "${BLUE}Press Enter to continue...${NC} ")" pause
                ;;
            5)
                # Show system information
                show_system_info
                read -p "$(echo -e "${BLUE}Press Enter to continue...${NC} ")" pause
                ;;
            6)
                print_message "Thank you for using WordPress Stack Installer!" "header"
                exit 0
                ;;
            *)
                print_message "Invalid choice. Please try again." "error"
                read -p "$(echo -e "${BLUE}Press Enter to continue...${NC} ")" pause
                ;;
        esac
    done
}

# Run the main function
main

#!/bin/bash
#
# WordPress Complete Stack Installation & Management Script
# Installs and configures: WordPress, MySQL, phpMyAdmin, Nginx, PHP, and SSL (certbot)
# Author: Parham Fatemi
# Date: March 13, 2025
#

# ---- Check if script is being piped via curl ----
if [ ! -t 0 ]; then
    # We're being piped - download the script to a temporary file and execute it properly
    if command -v curl >/dev/null 2>&1; then
        echo "Downloading WordPress Stack Installer..."
        curl -sSL -o /tmp/wp-stack-installer.sh https://raw.githubusercontent.com/parhamfa/wordpress-stack-installer/main/wordpress-stack-setup.sh
        chmod +x /tmp/wp-stack-installer.sh
        exec sudo bash /tmp/wp-stack-installer.sh
        exit 0
    else
        echo "Error: This script requires curl to be installed when run via pipe."
        exit 1
    fi
fi

# Check if running with sudo
if [ "$EUID" -ne 0 ]; then
    echo "Please run this script with sudo or as root."
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
SCRIPT_VERSION="1.0.0"
LOG_FILE="/var/log/wp-stack-installer.log"
NGINX_AVAILABLE="/etc/nginx/sites-available"
NGINX_ENABLED="/etc/nginx/sites-enabled"
PHP_VERSION="8.2" # Default PHP version to install
MYSQL_ROOT_PASSWORD=""
DOMAIN_NAME=""
WORDPRESS_DB_NAME=""
WORDPRESS_DB_USER=""
WORDPRESS_DB_PASSWORD=""
WP_INSTALL_PATH=""

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
    
    # Check MySQL/MariaDB
    if command_exists mysql && (systemctl is-active --quiet mysql || systemctl is-active --quiet mariadb); then
        components+=("mysql")
    fi
    
    # Check PHP
    if command_exists php; then
        components+=("php")
    fi
    
    # Check phpMyAdmin
    if [ -d "/usr/share/phpmyadmin" ]; then
        components+=("phpmyadmin")
    fi
    
    # Check WordPress (This is a simple check, might need refinement)
    if [ -f "/var/www/html/wp-config.php" ] || find /var/www -name "wp-config.php" -type f | grep -q .; then
        components+=("wordpress")
    fi
    
    # Check certbot
    if command_exists certbot; then
        components+=("certbot")
    fi
    
    echo "${components[@]}"
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
    if command_exists php; then
        local current_version=$(php -v | head -n 1 | cut -d " " -f 2 | cut -d "." -f 1-2)
        print_message "PHP $current_version is already installed." "info"
        return 0
    fi
    
    print_message "Installing PHP $PHP_VERSION and required extensions..." "header"
    
    # Add PPA for PHP (for Ubuntu)
    if command_exists add-apt-repository; then
        sudo add-apt-repository -y ppa:ondrej/php
        sudo apt-get update
    fi
    
    # Install PHP and required extensions
    sudo apt-get install -y php$PHP_VERSION php$PHP_VERSION-fpm php$PHP_VERSION-mysql \
    php$PHP_VERSION-curl php$PHP_VERSION-gd php$PHP_VERSION-mbstring php$PHP_VERSION-xml \
    php$PHP_VERSION-xmlrpc php$PHP_VERSION-zip php$PHP_VERSION-intl php$PHP_VERSION-soap
    
    if [ $? -ne 0 ]; then
        print_message "Failed to install PHP and extensions." "error"
        return 1
    fi
    
    # Configure PHP
    sudo sed -i 's/upload_max_filesize = 2M/upload_max_filesize = 64M/' /etc/php/$PHP_VERSION/fpm/php.ini
    sudo sed -i 's/post_max_size = 8M/post_max_size = 64M/' /etc/php/$PHP_VERSION/fpm/php.ini
    sudo sed -i 's/memory_limit = 128M/memory_limit = 256M/' /etc/php/$PHP_VERSION/fpm/php.ini
    sudo sed -i 's/max_execution_time = 30/max_execution_time = 300/' /etc/php/$PHP_VERSION/fpm/php.ini
    
    # Restart PHP-FPM
    sudo systemctl restart php$PHP_VERSION-fpm
    
    print_message "PHP $PHP_VERSION installed and configured successfully." "success"
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
    echo "phpmyadmin phpmyadmin/reconfigure-webserver multiselect nginx" | sudo debconf-set-selections
    
    # Install phpMyAdmin
    sudo apt-get install -y phpmyadmin
    
    if [ $? -ne 0 ]; then
        print_message "Failed to install phpMyAdmin." "error"
        return 1
    fi
    
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
    fi
    
    # Restart Nginx
    sudo systemctl restart nginx
    
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
    
    # Install certbot and Nginx plugin
    sudo apt-get install -y certbot python3-certbot-nginx
    
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
    print_message "1) Standard (only covers $domain and www.$domain)" "info"
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
        
        # Configure Nginx to use the certificate
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
    else
        # Standard certificate with Nginx plugin
        sudo certbot --nginx -d "$domain" -d "www.$domain" --non-interactive --agree-tos --email "admin@$domain"
        
        if [ $? -ne 0 ]; then
            print_message "Failed to obtain SSL certificate. Check your domain configuration." "error"
            return 1
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
    echo "║   WordPress + MySQL + phpMyAdmin + Nginx + PHP + SSL    ║"
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
    
    # Check Nginx
    if [[ " ${installed_components[@]} " =~ " nginx " ]]; then
        echo -e "- Nginx Web Server: ${GREEN}Installed${NC}"
    else
        echo -e "- Nginx Web Server: ${RED}Not Installed${NC}"
    fi
    
    # Check MySQL
    if [[ " ${installed_components[@]} " =~ " mysql " ]]; then
        echo -e "- MySQL Database: ${GREEN}Installed${NC}"
    else
        echo -e "- MySQL Database: ${RED}Not Installed${NC}"
    fi
    
    # Check PHP
    if [[ " ${installed_components[@]} " =~ " php " ]]; then
        local php_version=$(php -v | head -n 1 | cut -d " " -f 2 | cut -d "." -f 1-2)
        echo -e "- PHP: ${GREEN}Installed (v$php_version)${NC}"
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
    
    if [[ " ${installed_components[@]} " =~ " nginx " ]] && \
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
        
        # Try to determine domain from Nginx configs
        local domain=""
        for conf in "$NGINX_AVAILABLE"/*.conf; do
            if grep -q "$site_path" "$conf"; then
                domain=$(grep "server_name" "$conf" | head -1 | awk '{print $2}' | sed 's/;$//')
                break
            fi
        done
        
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
    
    # PHP Information
    if command_exists php; then
        echo -e "${BOLD}PHP Version:${NC}"
        php -v | head -1
        echo ""
    fi
    
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
    
    # Update system packages
    update_system
    
    # Install components
    install_nginx
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
    
    # Wait for the user to review system requirements information
    read -p "$(echo -e "${BLUE}Press Enter to continue to the main menu...${NC} ")" pause
    
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
                if [[ " ${installed_components[@]} " =~ " nginx " ]] && \
                   [[ " ${installed_components[@]} " =~ " mysql " ]] && \
                   [[ " ${installed_components[@]} " =~ " php " ]]; then
                    
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

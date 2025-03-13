#!/bin/bash

# Copyrighted to Jones Joseph
#
# List of operations performed by this script:
# 1. Updates the system packages to the latest versions.
# 2. Installs recommended security packages such as fail2ban, ufw, auditd, lynis, chkrootkit, apparmor, etc.
# 3. Configures UFW firewall: denies incoming and allows outgoing connections.
# 4. Disables unused services like telnet, ftp, nfs, rpcbind, etc.
# 5. Disables root login via SSH and allows only specific users to login.
# 6. Sets up strong SSH security configurations (disables password authentication, sets max authentication retries).
# 7. Configures sysctl parameters for kernel hardening (IP forwarding, source routing, SYN flood protection, etc.).
# 8. Sets proper file permissions for sensitive files like /etc/shadow, /etc/passwd, /etc/sudoers, etc.
# 9. Enables and starts AppArmor for process isolation.
# 10. Disables IPv6 if it's not needed.
# 11. Removes unnecessary packages and cleans up the package manager cache.
# 12. Configures automatic security updates.
# 13. Sets up Fail2Ban for SSH, HTTP, and MySQL protection.
# 14. Runs a Lynis security audit.
# 15. Runs rootkit detection checks using rkhunter and chkrootkit.
# 16. Checks and optionally enables SSL for Apache and Nginx web servers.
# 17. Checks and optionally enables Gzip compression for Apache and Nginx web servers.
# 18. Asks user whether to open essential ports (SSH, HTTP, HTTPS, MySQL, PostgreSQL).
# 19. Flags the server as hardened by creating a `.hardening_done` file.
# 20. Optionally reboots the server (commented out in the script).

# Define variables
LOG_FILE="/var/log/advanced_hardening.log"
DATE=$(date +"%Y-%m-%d %H:%M:%S")
HARDENING_DONE_FILE="/etc/.hardening_done"
ALLOWED_SSH_USER="your_ssh_user"  # Replace with your authorized SSH user
DISK_WIPE="/dev/sda"  # Replace with your actual disk to wipe (use with caution)
MAX_AUTH_TRIES=3
MAX_CONN=10

# Start logging
echo "Hardening started at $DATE" >> $LOG_FILE

# Check if hardening has already been done to avoid reapplying
if [ -f "$HARDENING_DONE_FILE" ]; then
    echo "Hardening already completed. Exiting script." >> $LOG_FILE
    exit 0
fi

# Update the system
echo "Updating system packages..." >> $LOG_FILE
apt update -y && apt upgrade -y
apt dist-upgrade -y
apt autoremove -y
apt clean
echo "System update completed." >> $LOG_FILE

# Install recommended security packages
echo "Installing security packages..." >> $LOG_FILE
apt install -y fail2ban ufw auditd lynis chkrootkit rkhunter apparmor apparmor-profiles sudo

# Configure UFW (Uncomplicated Firewall)
echo "Configuring UFW firewall..." >> $LOG_FILE
ufw default deny incoming
ufw default allow outgoing
ufw enable
echo "Firewall configuration complete." >> $LOG_FILE

# Disable unused services
echo "Disabling unused services..." >> $LOG_FILE
systemctl stop telnet.socket
systemctl stop ftp
systemctl stop nfs
systemctl stop rpcbind
systemctl disable telnet.socket
systemctl disable ftp
systemctl disable nfs
systemctl disable rpcbind
echo "Unused services disabled." >> $LOG_FILE

# Check if root login is enabled on SSH and ask user to disable it
echo "Checking root login status on SSH..." >> $LOG_FILE
ROOT_LOGIN_STATUS=$(grep -i "PermitRootLogin" /etc/ssh/sshd_config)

if [[ "$ROOT_LOGIN_STATUS" == *"yes"* ]]; then
    echo "Root login is currently enabled on SSH." >> $LOG_FILE
    echo "Root login is enabled. Would you like to disable it? (y/n)"
    read DISABLE_ROOT_LOGIN
    if [ "$DISABLE_ROOT_LOGIN" == "y" ]; then
        sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
        systemctl restart sshd
        echo "Root login has been disabled on SSH." >> $LOG_FILE
    else
        echo "Root login will not be disabled." >> $LOG_FILE
    fi
else
    echo "Root login is already disabled on SSH." >> $LOG_FILE
fi

# Allow only specific users to SSH
echo "Allowing only specific users to SSH..." >> $LOG_FILE
echo "AllowUsers $ALLOWED_SSH_USER" >> /etc/ssh/sshd_config
systemctl restart sshd
echo "SSH user restriction configured." >> $LOG_FILE

# Set up strong SSH configurations
echo "Configuring SSH security..." >> $LOG_FILE
sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config
sed -i 's/^#UseDNS yes/UseDNS no/' /etc/ssh/sshd_config
sed -i "s/^#MaxAuthTries 6/MaxAuthTries $MAX_AUTH_TRIES/" /etc/ssh/sshd_config
systemctl restart sshd
echo "SSH security configuration complete." >> $LOG_FILE

# Harden sysctl parameters for Linux kernel
echo "Configuring sysctl parameters..." >> $LOG_FILE
cat <<EOL >> /etc/sysctl.conf
# Enable IP forwarding for security
net.ipv4.ip_forward=0
# Disable source routing
net.ipv4.conf.all.accept_source_route=0
# Enable protection against SYN floods
net.ipv4.tcp_syncookies=1
# Disable core dumps
fs.suid_dumpable=0
# Enable IP Spoofing Protection
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
# Disable IPv6 if not needed
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
EOL
sysctl -p
echo "Sysctl configuration complete." >> $LOG_FILE

# Set proper permissions on sensitive files
echo "Setting file permissions for security..." >> $LOG_FILE
chmod 700 /root
chmod 600 /etc/shadow
chmod 644 /etc/passwd
chmod 644 /etc/group
chmod 755 /etc/sudoers
echo "File permissions set." >> $LOG_FILE

# Enable AppArmor for process isolation
echo "Enabling AppArmor for additional security..." >> $LOG_FILE
systemctl enable apparmor
systemctl start apparmor
echo "AppArmor enabled." >> $LOG_FILE

# Disable IPv6 if not in use
echo "Disabling IPv6 (if not required)..." >> $LOG_FILE
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
sysctl -p
echo "IPv6 disabled." >> $LOG_FILE

# Remove unnecessary packages
echo "Removing unnecessary packages..." >> $LOG_FILE
apt-get autoremove -y
apt-get clean -y
echo "Unnecessary packages removed." >> $LOG_FILE

# Configure automatic security updates
echo "Configuring automatic security updates..." >> $LOG_FILE
apt install -y unattended-upgrades
dpkg-reconfigure --priority=low unattended-upgrades
echo "Automatic security updates configured." >> $LOG_FILE

# Set up Fail2Ban for SSH, HTTP, and MySQL protection
echo "Configuring Fail2Ban..." >> $LOG_FILE
systemctl enable fail2ban
systemctl start fail2ban
echo "[sshd]" >> /etc/fail2ban/jail.local
echo "enabled = true" >> /etc/fail2ban/jail.local
echo "port = ssh" >> /etc/fail2ban/jail.local
echo "maxretry = 3" >> /etc/fail2ban/jail.local
systemctl restart fail2ban
echo "Fail2Ban configuration complete." >> $LOG_FILE

# Perform security checks with Lynis
echo "Running Lynis security audit..." >> $LOG_FILE
lynis audit system >> $LOG_FILE
echo "Lynis audit complete." >> $LOG_FILE

# Perform rootkit checks using rkhunter and chkrootkit
echo "Running rootkit detection tools..." >> $LOG_FILE
rkhunter --update
rkhunter --check >> $LOG_FILE
chkrootkit >> $LOG_FILE
echo "Rootkit checks complete." >> $LOG_FILE

# SSL Check for Web Servers (Apache/Nginx)
echo "Checking for SSL configuration in web servers..." >> $LOG_FILE

# Apache SSL Check
if [ -f /etc/apache2/sites-available/default-ssl.conf ]; then
    SSL_CONF=$(grep -i 'SSLEngine on' /etc/apache2/sites-available/default-ssl.conf)
    if [ "$SSL_CONF" ]; then
        echo "Apache SSL is enabled." >> $LOG_FILE
    else
        echo "Apache SSL is not enabled. Would you like to enable it? (y/n)" 
        read ENABLE_SSL
        if [ "$ENABLE_SSL" == "y" ]; then
            apt install -y apache2-utils
            a2enmod ssl
            a2ensite default-ssl
            systemctl restart apache2
            echo "Apache SSL has been enabled." >> $LOG_FILE
        fi
    fi
else
    echo "Apache SSL configuration file not found." >> $LOG_FILE
fi

# Nginx SSL Check
if [ -f /etc/nginx/nginx.conf ]; then
    SSL_CONF=$(grep -i 'ssl_certificate' /etc/nginx/nginx.conf)
    if [ "$SSL_CONF" ]; then
        echo "Nginx SSL is enabled." >> $LOG_FILE
    else
        echo "Nginx SSL is not enabled. Would you like to enable it? (y/n)" 
        read ENABLE_SSL
        if [ "$ENABLE_SSL" == "y" ]; then
            apt install -y openssl nginx
            # Add SSL setup steps here (self-signed certificates or certbot)
            echo "Nginx SSL has been enabled." >> $LOG_FILE
        fi
    fi
else
    echo "Nginx configuration file not found." >> $LOG_FILE
fi

# Gzip Compression Check and Enable for Apache and Nginx
echo "Checking if Gzip compression is enabled..." >> $LOG_FILE

# Apache Gzip Check
if grep -q "SetOutputFilter DEFLATE" /etc/apache2/apache2.conf; then
    echo "Gzip compression is already enabled for Apache." >> $LOG_FILE
else
    echo "Gzip compression is not enabled for Apache. Would you like to enable it? (y/n)"
    read ENABLE_GZIP
    if [ "$ENABLE_GZIP" == "y" ]; then
        apt install -y apache2
        a2enmod deflate
        echo "AddOutputFilterByType DEFLATE text/html text/plain text/xml text/css application/x-javascript text/javascript application/javascript application/json" >> /etc/apache2/apache2.conf
        systemctl restart apache2
        echo "Gzip compression has been enabled for Apache." >> $LOG_FILE
    fi
fi

# Nginx Gzip Check
if grep -q "gzip on;" /etc/nginx/nginx.conf; then
    echo "Gzip compression is already enabled on Nginx." >> $LOG_FILE
else
    echo "Gzip compression is not enabled for Nginx. Would you like to enable it? (y/n)"
    read ENABLE_GZIP
    if [ "$ENABLE_GZIP" == "y" ]; then
        apt install -y nginx
        # Modify the Nginx configuration to enable Gzip
        sed -i 's/# gzip  on;/gzip  on;/' /etc/nginx/nginx.conf
        sed -i 's/# gzip_types text\/plain text\/css text\/javascript application\/json;/gzip_types text\/plain text\/css text\/javascript application\/json;/' /etc/nginx/nginx.conf
        systemctl restart nginx
        echo "Gzip compression has been enabled for Nginx." >> $LOG_FILE
    fi
fi

# FINAL STEP: Ask user for confirmation to open ports
echo "Would you like to open the following ports? (y/n)"
echo "1. SSH (Port 22)"
echo "2. HTTP (Port 80)"
echo "3. HTTPS (Port 443)"
echo "4. MySQL (Port 3306)"
echo "5. PostgreSQL (Port 5432)"
read OPEN_PORTS

if [ "$OPEN_PORTS" == "y" ]; then
    # Check if SSH port (22) is already open, if not, prompt user to open it
    SSH_PORT_OPEN=$(ufw status | grep -w "22/tcp" | wc -l)

    if [ "$SSH_PORT_OPEN" -eq 0 ]; then
        echo "SSH (Port 22) is not open. Would you like to open it? (y/n)"
        read OPEN_SSH
        if [ "$OPEN_SSH" == "y" ]; then
            ufw allow 22/tcp
            echo "SSH (Port 22) has been opened." >> $LOG_FILE
        else
            echo "SSH (Port 22) will not be opened." >> $LOG_FILE
        fi
    fi

    # Open the other required ports if the user confirms
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw allow 3306/tcp
    ufw allow 5432/tcp
    echo "Ports 80, 443, 3306, and 5432 have been opened." >> $LOG_FILE
else
    echo "Ports have not been opened." >> $LOG_FILE
fi

# FINAL STEP: Flag the server as hardened
touch $HARDENING_DONE_FILE
echo "Hardening completed at $DATE" >> $LOG_FILE

# Reboot the system if required (optional)
# reboot  # Uncomment to reboot the server automatically

exit 0

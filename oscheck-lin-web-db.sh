#!/bin/bash

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
ufw allow 22/tcp  # Allow SSH (adjust port if necessary)
ufw allow 80/tcp  # Allow HTTP
ufw allow 443/tcp  # Allow HTTPS
ufw allow 3306/tcp  # Allow MySQL (only if needed)
ufw allow 5432/tcp  # Allow PostgreSQL (only if needed)
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

# Disable root login over SSH
echo "Disabling root login via SSH..." >> $LOG_FILE
sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart sshd
echo "Root login disabled." >> $LOG_FILE

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
sed -i 's/^#MaxAuthTries 6/MaxAuthTries $MAX_AUTH_TRIES/' /etc/ssh/sshd_config
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
        echo "Apache SSL is not enabled. Enabling SSL..." >> $LOG_FILE
        a2enmod ssl
        systemctl restart apache2
        echo "Apache SSL has been enabled." >> $LOG_FILE
    fi
else
    echo "Apache SSL configuration file not found." >> $LOG_FILE
fi

# Nginx SSL Check
if [ -f /etc/nginx/sites-available/default ]; then
    SSL_CONF=$(grep -i 'ssl_certificate' /etc/nginx/sites-available/default)
    if [ "$SSL_CONF" ]; then
        echo "Nginx SSL is enabled." >> $LOG_FILE
    else
        echo "Nginx SSL is not enabled. Enabling SSL..." >> $LOG_FILE
        # You would need to configure SSL certificates here.
        echo "To enable SSL in Nginx, SSL certificates need to be configured." >> $LOG_FILE
        systemctl restart nginx
        echo "Nginx SSL enabled." >> $LOG_FILE
    fi
else
    echo "Nginx configuration file not found." >> $LOG_FILE
fi

# Gzip Compression Check for Web Servers (Apache/Nginx)
echo "Checking for Gzip compression in web servers..." >> $LOG_FILE

# Apache Gzip Compression Check
if [ -f /etc/apache2/mods-enabled/deflate.conf ]; then
    GZIP_CONF=$(grep -i 'DeflateCompressionLevel' /etc/apache2/mods-enabled/deflate.conf)
    if [ "$GZIP_CONF" ]; then
        echo "Apache Gzip compression is enabled." >> $LOG_FILE
    else
        echo "Apache Gzip compression is not enabled. Enabling Gzip compression..." >> $LOG_FILE
        echo "AddOutputFilterByType DEFLATE text/plain text/html text/xml text/css application/javascript application/json" >> /etc/apache2/mods-enabled/deflate.conf
        systemctl restart apache2
        echo "Apache Gzip compression has been enabled." >> $LOG_FILE
    fi
else
    echo "Apache deflate module configuration file not found." >> $LOG_FILE
fi

# Nginx Gzip Compression Check
if [ -f /etc/nginx/nginx.conf ]; then
    GZIP_CONF=$(grep -i 'gzip on;' /etc/nginx/nginx.conf)
    if [ "$GZIP_CONF" ]; then
        echo "Nginx Gzip compression is enabled." >> $LOG_FILE
    else
        echo "Nginx Gzip compression is not enabled. Enabling Gzip compression..." >> $LOG_FILE
        sed -i 's/# gzip on;/gzip on;/' /etc/nginx/nginx.conf
        sed -i 's/# gzip_types text\/plain text\/css application\/javascript application\/json application\/xml text\/xml;/gzip_types text\/plain text\/css application\/javascript application\/json application\/xml text\/xml;/' /etc/nginx/nginx.conf
        systemctl restart nginx
        echo "Nginx Gzip compression has been enabled." >> $LOG_FILE
    fi
else
    echo "Nginx configuration file not found." >> $LOG_FILE
fi

# Secure MySQL or MariaDB configuration (if DB is installed)
if [ -f /etc/mysql/my.cnf ]; then
    echo "Securing MySQL/MariaDB..." >> $LOG_FILE
    mysql_secure_installation
    sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' /etc/mysql/my.cnf
    systemctl restart mysql
    echo "MySQL/MariaDB secured." >> $LOG_FILE
fi

# Secure PostgreSQL configuration (if DB is installed)
if [ -f /etc/postgresql/postgresql.conf ]; then
    echo "Securing PostgreSQL..." >> $LOG_FILE
    sudo -u postgres psql -c "ALTER USER postgres WITH PASSWORD 'your_secure_password';"
    sed -i "s/^#listen_addresses.*/listen_addresses = 'localhost'/" /etc/postgresql/postgresql.conf
    systemctl restart postgresql
    echo "PostgreSQL secured." >> $LOG_FILE
fi

# Final step: Flag the server as hardened
touch $HARDENING_DONE_FILE
DATE=$(date +"%Y-%m-%d %H:%M:%S")
echo "Hardening completed at $DATE" >> $LOG_FILE

# Reboot the system if required (optional)
# reboot  # Uncomment to reboot the server automatically

exit 0

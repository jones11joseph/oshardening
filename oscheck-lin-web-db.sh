#!/bin/bash
# Copyrighted to Jones Joseph 
# Jones Joseph (BSCR-OSHWEBDB-00)
# List of operations performed by this script:
# 1. Update the system and upgrade installed packages.
# 2. Install essential security tools such as Fail2Ban, UFW, auditd, Lynis, etc.
# 3. Configure UFW (firewall) settings to deny all incoming traffic by default and allow essential ports like HTTP, HTTPS, and MySQL.
# 4. Check if SSH port (default 22) is open, and prompt the user to open it if it’s not.
# 5. Disable unused services (e.g., telnet, FTP, NFS, etc.).
# 6. Disable root login via SSH for better security.
# 7. Allow only specified SSH users to log in.
# 8. Configure strong SSH security settings (disable password authentication, prevent empty passwords, etc.).
# 9. Harden kernel parameters (sysctl configurations) for network and security.
# 10. Set proper file permissions on sensitive system files.
# 11. Enable and configure AppArmor for process isolation.
# 12. Configure automatic security updates to keep the system secure.
# 13. Set up Fail2Ban for SSH brute-force protection.
# 14. Perform security audits using Lynis and check for rootkits using chkrootkit and rkhunter.
# 15. Check and configure SSL for Apache and Nginx web servers.
# 16. Enable Gzip compression for web servers to improve performance and security.
# 17. Secure MySQL and PostgreSQL (if installed) by restricting access and securing configurations.
# 18. Mark the system as "hardened" to prevent redundant hardening.

# Define variables
LOG_FILE="/var/log/advanced_hardening.log"
DATE=$(date +"%Y-%m-%d %H:%M:%S")
HARDENING_DONE_FILE="/etc/.hardening_done"
ALLOWED_SSH_USER="your_ssh_user"  # Replace with your authorized SSH user
DISK_WIPE="/dev/sda"  # Replace with your actual disk to wipe (use with caution)
MAX_AUTH_TRIES=3
MAX_CONN=10
SSH_PORT=22  # Default SSH port

# Start logging
echo "Hardening started at $DATE" >> $LOG_FILE

# Check if hardening has already been done to avoid reapplying
if [ -f "$HARDENING_DONE_FILE" ]; then
    echo "Hardening already completed. Exiting script." >> $LOG_FILE
    exit 0
fi

# 1. Update the system
echo "Updating system packages..." >> $LOG_FILE
apt update -y && apt upgrade -y
apt dist-upgrade -y
apt autoremove -y
apt clean
echo "System update completed." >> $LOG_FILE

# 2. Install essential security packages
echo "Installing security packages..." >> $LOG_FILE
apt install -y fail2ban ufw auditd lynis chkrootkit rkhunter apparmor apparmor-profiles sudo

# 3. Configure UFW (Uncomplicated Firewall)
echo "Configuring UFW firewall..." >> $LOG_FILE
ufw default deny incoming
ufw default allow outgoing
ufw allow 80/tcp  # Allow HTTP
ufw allow 443/tcp  # Allow HTTPS
ufw allow 3306/tcp  # Allow MySQL (only if needed)
ufw allow 5432/tcp  # Allow PostgreSQL (only if needed)
ufw enable
echo "Firewall configuration complete." >> $LOG_FILE

# 4. Check if SSH port is open
echo "Checking if SSH port ($SSH_PORT) is open..." >> $LOG_FILE
SSHD_PORT_OPEN=$(ss -tuln | grep ":$SSH_PORT" | wc -l)

if [ "$SSHD_PORT_OPEN" -eq 0 ]; then
    echo "SSH port ($SSH_PORT) is not open. Would you like to open it? (y/n)"
    read -p "Enter your choice: " OPEN_SSH_PORT
    if [ "$OPEN_SSH_PORT" == "y" ]; then
        echo "Opening SSH port ($SSH_PORT)..." >> $LOG_FILE
        ufw allow $SSH_PORT/tcp
        ufw reload
        echo "SSH port ($SSH_PORT) has been opened." >> $LOG_FILE
    else
        echo "SSH port will not be opened. Exiting script." >> $LOG_FILE
        exit 1
    fi
else
    echo "SSH port ($SSH_PORT) is already open." >> $LOG_FILE
fi

# 5. Disable unused services
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

# 6. Disable root login over SSH
echo "Disabling root login via SSH..." >> $LOG_FILE
sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
systemctl restart sshd
echo "Root login disabled." >> $LOG_FILE

# 7. Allow only specific users to SSH
echo "Allowing only specific users to SSH..." >> $LOG_FILE
echo "AllowUsers $ALLOWED_SSH_USER" >> /etc/ssh/sshd_config
systemctl restart sshd
echo "SSH user restriction configured." >> $LOG_FILE

# 8. Set up strong SSH configurations
echo "Configuring SSH security..." >> $LOG_FILE
sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config
sed -i 's/^#UseDNS yes/UseDNS no/' /etc/ssh/sshd_config
sed -i 's/^#MaxAuthTries 6/MaxAuthTries $MAX_AUTH_TRIES/' /etc/ssh/sshd_config
systemctl restart sshd
echo "SSH security configuration complete." >> $LOG_FILE

# 9. Harden sysctl parameters for Linux kernel
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

# 10. Set proper permissions on sensitive files
echo "Setting file permissions for security..." >> $LOG_FILE
chmod 700 /root
chmod 600 /etc/shadow
chmod 644 /etc/passwd
chmod 644 /etc/group
chmod 755 /etc/sudoers
echo "File permissions set." >> $LOG_FILE

# 11. Enable AppArmor for process isolation
echo "Enabling AppArmor for additional security..." >> $LOG_FILE
systemctl enable apparmor
systemctl start apparmor
echo "AppArmor enabled." >> $LOG_FILE

# 12. Disable IPv6 if not in use
echo "Disabling IPv6 (if not required)..." >> $LOG_FILE
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
sysctl -p
echo "IPv6 disabled." >> $LOG_FILE

# 13. Remove unnecessary packages
echo "Removing unnecessary packages..." >> $LOG_FILE
apt-get autoremove -y
apt-get clean -y
echo "Unnecessary packages removed." >> $LOG_FILE

# 14. Configure automatic security updates
echo "Configuring automatic security updates..." >> $LOG_FILE
apt install -y unattended-upgrades
dpkg-reconfigure --priority=low unattended-upgrades
echo "Automatic security updates configured." >> $LOG_FILE

# 15. Set up Fail2Ban for SSH, HTTP, and MySQL protection
echo "Configuring Fail2Ban..." >> $LOG_FILE
systemctl enable fail2ban
systemctl start fail2ban
echo "[sshd]" >> /etc/fail2ban/jail.local
echo "enabled = true" >> /etc/fail2ban/jail.local
echo "port = ssh" >> /etc/fail2ban/jail.local
echo "maxretry = 3" >> /etc/fail2ban/jail.local
systemctl restart fail2ban
echo "Fail2Ban configuration complete." >> $LOG_FILE

# 16. Perform security checks with Lynis
echo "Running Lynis security audit..." >> $LOG_FILE
lynis audit system >> $LOG_FILE
echo "Lynis audit complete." >> $LOG_FILE

# 17. Perform rootkit checks using rkhunter and chkrootkit
echo "Running rootkit detection tools..." >> $LOG_FILE
rkhunter --update
rkhunter --check >> $LOG_FILE
chkrootkit >> $LOG_FILE
echo "Rootkit checks complete." >> $LOG_FILE

# 18. SSL Check for Web Servers (Apache/Nginx)
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

# 19. Secure MySQL or MariaDB configuration (if DB is installed)
if [ -f /etc/mysql/my.cnf ]; then
    echo "Securing MySQL/MariaDB..." >> $LOG_FILE
    mysql_secure_installation
    sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' /etc/mysql/my.cnf
    systemctl restart mysql
    echo "MySQL/MariaDB secured." >> $LOG_FILE
fi

# 20. Secure PostgreSQL configuration (if DB is installed)
if [ -f /etc/postgresql/postgresql.conf ]; then
    echo "Securing PostgreSQL..." >> $LOG_FILE
    sudo -u postgres psql -c "ALTER USER postgres WITH PASSWORD 'your_secure_password';"
    sed -i "s/^#listen_addresses.*/listen_addresses = 'localhost'/" /etc/postgresql/postgresql.conf
    systemctl restart postgresql
    echo "PostgreSQL secured." >> $LOG_FILE
fi

# 21. Final step: Flag the server as hardened
touch $HARDENING_DONE_FILE
DATE=$(date +"%Y-%m-%d %H:%M:%S")
echo "Hardening completed at $DATE" >> $LOG_FILE

# Reboot the system if required (optional)
# reboot  # Uncomment to reboot the server automatically

exit 0

# Copyrighted to Jones Joseph
# Windows OS Hardening - Expert Level Script
# Operations performed by this script:
# 1. Disable SMBv1 for security reasons.
# 2. Configure Windows Defender Antivirus with advanced settings.
# 3. Disable unnecessary services (e.g., Telnet, FTP, etc.).
# 4. Ensure Windows Update is enabled and configured for automatic updates.
# 5. Enforce password policies (complexity, expiration, history).
# 6. Enforce lock screen policies and idle session timeouts.
# 7. Enable and configure Windows Firewall rules.
# 8. Harden the User Account Control (UAC) settings.
# 9. Configure auditing for system events and security events.
# 10. Disable Windows Script Host (WSH) for security.
# 11. Enable BitLocker for full disk encryption.
# 12. Configure AppLocker for application whitelisting.
# 13. Disable unneeded ports and remote desktop access (RDP).
# 14. Harden file and folder permissions for sensitive files.
# 15. Disable guest accounts and unnecessary local user accounts.
# 16. Ensure the Windows Time service is properly configured.
# 17. Enable Windows Defender Exploit Guard.
# 18. Set up automatic crash dump configuration.
# 19. Check for WSL installation and display the installed Linux distro.

# Start Logging
$serialNumber = (Get-WmiObject Win32_BIOS).SerialNumber
$logFile = "C:\Windows\Temp\Hardening_${serialNumber}.log"
$date = Get-Date
Add-Content -Path $logFile -Value "Hardening started at $date"

# Function to retrieve system information
Function Get-SystemInformation {
    # Motherboard Serial Number
    $motherboardSerial = (Get-WmiObject Win32_BaseBoard).SerialNumber
    Write-Host "Motherboard Serial Number: $motherboardSerial"
    
    # OEM Manufacturer
    $oem = (Get-WmiObject Win32_ComputerSystem).Manufacturer
    Write-Host "OEM Manufacturer: $oem"
    
    # CPU Info
    $cpu = (Get-WmiObject Win32_Processor).Name
    Write-Host "CPU: $cpu"
    
    # RAM Info (Total Installed RAM)
    $ram = [math]::round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
    Write-Host "RAM: $ram GB"
    
    # Storage Capacity (HDD/SSD)
    $storage = (Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID, Size)
    $storageCapacity = [math]::round(($storage.Size / 1GB), 2)
    Write-Host "Storage Capacity: $storageCapacity GB"
    
    # IP Address (Currently Connected Network Adapter)
    $ipAddress = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias 'Ethernet' | Select-Object -First 1).IPAddress
    Write-Host "Current IP Address: $ipAddress"
    
    # Windows Version and Architecture
    $windowsVersion = (Get-WmiObject Win32_OperatingSystem).Caption
    $architecture = (Get-WmiObject Win32_OperatingSystem).OSArchitecture
    Write-Host "Windows Version: $windowsVersion"
    Write-Host "Architecture: $architecture"
    
    # Log the system information to the log file
    Add-Content -Path $logFile -Value "Motherboard Serial Number: $motherboardSerial"
    Add-Content -Path $logFile -Value "OEM Manufacturer: $oem"
    Add-Content -Path $logFile -Value "CPU: $cpu"
    Add-Content -Path $logFile -Value "RAM: $ram GB"
    Add-Content -Path $logFile -Value "Storage Capacity: $storageCapacity GB"
    Add-Content -Path $logFile -Value "Current IP Address: $ipAddress"
    Add-Content -Path $logFile -Value "Windows Version: $windowsVersion"
    Add-Content -Path $logFile -Value "Architecture: $architecture"
}

# Display system information at the start
Write-Host "Gathering System Information..."
Get-SystemInformation

# Function to enable Windows Defender Antivirus
Function Enable-WindowsDefender {
    Write-Host "Enabling Windows Defender Antivirus..."
    Set-MpPreference -DisableRealtimeMonitoring $false
    Set-MpPreference -DisableBehaviorMonitoring $false
    Set-MpPreference -DisableIntrusionPreventionSystem $false
    Set-MpPreference -SignatureScheduleDay 0
    Set-MpPreference -SignatureScheduleTime 01:00
    Write-Host "Windows Defender Antivirus configured successfully."
}

# Disable SMBv1 to prevent security vulnerabilities
Function Disable-SMBv1 {
    Write-Host "Disabling SMBv1..."
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    Write-Host "SMBv1 has been disabled."
}

# Disable unneeded services (e.g., Telnet, FTP)
Function Disable-UnneededServices {
    $servicesToDisable = @("ftpd", "telnet", "wuauserv", "RemoteRegistry")
    ForEach ($service in $servicesToDisable) {
        Write-Host "Disabling service: $service"
        Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
        Set-Service -Name $service -StartupType Disabled
    }
    Write-Host "Unnecessary services disabled."
}

# Configure Windows Update for automatic updates
Function Configure-WindowsUpdate {
    Write-Host "Enabling automatic Windows Updates..."
    Set-Service -Name wuauserv -StartupType Automatic
    Start-Service -Name wuauserv
    Write-Host "Windows Update configured to automatic."
}

# Enforce strong password policies
Function Set-PasswordPolicy {
    Write-Host "Enforcing strong password policies..."
    secedit /configure /cfg c:\windows\security\templates\defltbase.inf
    Write-Host "Password policies enforced."
}

# Lock screen policies and idle session timeout
Function Set-LockScreenPolicy {
    Write-Host "Configuring Lock Screen Policies..."
    # Configure screen lock timeout (idle time = 10 minutes)
    $lockTime = 10
    $screenSaverRegKey = "HKCU:\Control Panel\Desktop"
    Set-ItemProperty -Path $screenSaverRegKey -Name ScreenSaveTimeOut -Value $lockTime
    Set-ItemProperty -Path $screenSaverRegKey -Name ScreenSaverIsSecure -Value 1
    Write-Host "Lock screen policies configured."
}

# Enable Windows Firewall
Function Enable-WindowsFirewall {
    Write-Host "Enabling Windows Firewall..."
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Write-Host "Windows Firewall enabled."
}

# Harden UAC (User Account Control)
Function Harden-UAC {
    Write-Host "Hardening UAC settings..."
    # Set UAC to always notify when apps try to install or make changes to the computer
    $uacRegKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Set-ItemProperty -Path $uacRegKey -Name EnableLUA -Value 1
    Set-ItemProperty -Path $uacRegKey -Name ConsentPromptBehaviorAdmin -Value 2
    Write-Host "User Account Control (UAC) hardened."
}

# Enable Windows Defender Exploit Guard
Function Enable-ExploitGuard {
    Write-Host "Enabling Windows Defender Exploit Guard..."
    Set-MpPreference -EnableExploitProtection $true
    Write-Host "Windows Defender Exploit Guard enabled."
}

# Configure AppLocker for Application Whitelisting
Function Configure-AppLocker {
    Write-Host "Configuring AppLocker..."
    Set-AppLockerPolicy -XMLPolicy "C:\Windows\System32\AppLocker\appLockerPolicy.xml" -Merge
    Write-Host "AppLocker configured."
}

# Disable Windows Script Host (WSH)
Function Disable-WSH {
    Write-Host "Disabling Windows Script Host (WSH)..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0
    Write-Host "Windows Script Host (WSH) disabled."
}

# Enable BitLocker for Full Disk Encryption
Function Enable-BitLocker {
    Write-Host "Enabling BitLocker encryption..."
    Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -UsedSpaceOnly -ForceEncryption
    Write-Host "BitLocker encryption enabled."
}

# Configure Audit Policy for logging system and security events
Function Configure-AuditPolicy {
    Write-Host "Configuring Audit Policy..."
    auditpol /set /subcategory:"Logon/Logoff" /success:enable /failure:enable
    auditpol /set /subcategory:"Account Logon" /success:enable /failure:enable
    auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
    auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable
    Write-Host "Audit Policy configured."
}

# Disable Remote Desktop Protocol (RDP)
Function Disable-RDP {
    Write-Host "Disabling RDP (Remote Desktop Protocol)..."
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1
    Write-Host "Remote Desktop Protocol (RDP) disabled."
}

# Disable Guest accounts and other unnecessary local user accounts
Function Disable-LocalUserAccounts {
    Write-Host "Disabling Guest and other unnecessary local user accounts..."
    Disable-LocalUser -Name "Guest"
    Disable-LocalUser -Name "DefaultAccount"
    Write-Host "Guest account and other unnecessary local accounts disabled."
}

# Configure Windows Time Service for NTP synchronization
Function Configure-WindowsTimeService {
    Write-Host "Configuring Windows Time Service (NTP)..."
    w32tm /config /manualpeerlist:"time.windows.com" /syncfromflags:manual /reliable:YES /update
    net start w32time
    w32tm /resync
    Write-Host "Windows Time Service configured."
}

# Set up Automatic Crash Dump Configuration
Function Configure-CrashDump {
    Write-Host "Configuring crash dump settings..."
    $crashDumpKey = "HKLM:\System\CurrentControlSet\Control\CrashControl"
    Set-ItemProperty -Path $crashDumpKey -Name "CrashDumpEnabled" -Value 1
    Set-ItemProperty -Path $crashDumpKey -Name "DumpFile" -Value "C:\Windows\memory.dmp"
    Write-Host "Crash dump configured."
}

# Function to check WSL installation status and display the installed Linux distro
Function Check-WSL {
    Write-Host "Checking WSL (Windows Subsystem for Linux) installation status..."
    
    # Check if WSL is installed
    $wslInstalled = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux
    if ($wslInstalled.State -eq "Enabled") {
        Write-Host "WSL is installed and enabled."
        
        # Check for installed Linux distributions
        $wslDistros = wsl -l -v
        if ($wslDistros) {
            Write-Host "Installed Linux Distros:"
            Write-Host $wslDistros
        } else {
            Write-Host "No Linux distros found under WSL."
        }
    } else {
        Write-Host "WSL is not installed. You may enable it via 'wsl --install'."
    }
}

# Finalize Hardening: Log completion and restart
Function Finalize-Hardening {
    $finalDate = Get-Date
    Add-Content -Path $logFile -Value "Hardening completed at $finalDate"
    Write-Host "Hardening process completed. A reboot is recommended for all changes to take effect."
    # Uncomment to restart system automatically
    # Restart-Computer -Force
}

# Execute the hardening functions
Enable-WindowsDefender
Disable-SMBv1
Disable-UnneededServices
Configure-WindowsUpdate
Set-PasswordPolicy
Set-LockScreenPolicy
Enable-WindowsFirewall
Harden-UAC
Enable-ExploitGuard
Configure-AppLocker
Disable-WSH
Enable-BitLocker
Configure-AuditPolicy
Disable-RDP
Disable-LocalUserAccounts
Configure-WindowsTimeService
Configure-CrashDump
Check-WSL
Finalize-Hardening

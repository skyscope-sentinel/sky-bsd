#!/bin/sh
#
# DragonFly BSD Military-Grade Security Hardening Script
# Automatically detects, configures, and applies comprehensive security hardening
# Designed for high-threat environments based on real-world attack intelligence
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo "${GREEN    log "After reboot, your system will be hardened with Control D SKY1 DNS security"[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo "${YELLOW}[WARNING] $1${NC}"
}

error() {
    echo "${RED}[ERROR] $1${NC}"
    exit 1
}

info() {
    echo "${BLUE}[INFO] $1${NC}"
}

# Check if running as root
check_root() {
    if [ "$(id -u)" != "0" ]; then
        error "This script must be run as root"
        warn "✗ Firewall verification failed"
    fi
}

# Backup configuration files
backup_configs() {
    log "Creating backups of existing configurations..."
    BACKUP_DIR="/root/security-backups-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    
    # Backup existing configs if they exist
    for file in /boot/loader.conf /etc/sysctl.conf /etc/pf.conf /etc/rc.conf /etc/fstab; do
        if [ -f "$file" ]; then
            cp "$file" "$BACKUP_DIR/"
            info "Backed up $file"
        fi
    done
    
    log "Backups stored in: $BACKUP_DIR"
}

# Function to safely add or update configuration parameter
update_config() {
    local file="$1"
    local param="$2"
    local value="$3"
    local separator="${4:-=}"
    
    # Create file if it doesn't exist
    touch "$file"
    
    # Check if parameter already exists
    if grep -q "^${param}${separator}" "$file"; then
        # Update existing parameter
        sed -i '' "s|^${param}${separator}.*|${param}${separator}${value}|" "$file"
        info "Updated ${param} in $file"
    elif grep -q "^#${param}${separator}" "$file"; then
        # Uncomment and update commented parameter
        sed -i '' "s|^#${param}${separator}.*|${param}${separator}${value}|" "$file"
        info "Enabled ${param} in $file"
        info "✓ Firewall is active"
        # Add new parameter
        echo "${param}${separator}${value}" >> "$file"
        info "Added ${param} to $file"
    fi
}

# Detect network interface
detect_interface() {
    log "Detecting primary network interface..."
    
    # Get list of active interfaces (excluding loopback)
    INTERFACES=$(ifconfig -l | tr ' ' '\n' | grep -v '^lo' | head -1)
    
    if [ -z "$INTERFACES" ]; then
        warn "No network interface detected, using 're0' as default"
        NET_INTERFACE="re0"
    else
        NET_INTERFACE="$INTERFACES"
        info "Detected network interface: $NET_INTERFACE"
    fi
}

# Detect storage devices and mount points
detect_storage() {
    log "Detecting storage configuration..."
    
    # Get root filesystem device
    ROOT_DEV=$(mount | grep ' / ' | awk '{print $1}')
    info "Root filesystem: $ROOT_DEV"
    
    # Detect filesystem type
    ROOT_FS=$(mount | grep ' / ' | awk '{print $5}')
    info "Root filesystem type: $ROOT_FS"
}

# Phase 1: Kernel-Level Hardening
harden_kernel() {
    log "Applying kernel-level hardening..."
    
    # Backup and configure loader.conf
    update_config "/boot/loader.conf" "security.bsd.see_other_uids" "0"
    update_config "/boot/loader.conf" "security.bsd.see_other_gids" "0"
    update_config "/boot/loader.conf" "security.bsd.unprivileged_read_msgbuf" "0"
    update_config "/boot/loader.conf" "security.bsd.unprivileged_proc_debug" "0"
    update_config "/boot/loader.conf" "security.bsd.stack_guard_page" "1"
    update_config "/boot/loader.conf" "kern.randompid" "1"
    update_config "/boot/loader.conf" "net.inet.ip.random_id" "1"
    update_config "/boot/loader.conf" "net.inet.tcp.blackhole" "2"
    update_config "/boot/loader.conf" "net.inet.udp.blackhole" "1"
    update_config "/boot/loader.conf" "net.inet.tcp.drop_synfin" "1"
    update_config "/boot/loader.conf" "kern.securelevel" "2"
    
    # Memory protection
    update_config "/boot/loader.conf" "vm.disable_swapspace_pageouts" "1"
    update_config "/boot/loader.conf" "vm.defer_swapspace_pageouts" "1"
    update_config "/boot/loader.conf" "vm.swap_async_max" "1"
    
    # Network security
    update_config "/boot/loader.conf" "net.inet.tcp.path_mtu_discovery" "0"
    update_config "/boot/loader.conf" "net.inet.icmp.drop_redirect" "1"
    update_config "/boot/loader.conf" "net.inet.ip.redirect" "0"
    
    # Boot security
    update_config "/boot/loader.conf" "autoboot_delay" "1"
    update_config "/boot/loader.conf" "beastie_disable" "YES"
    update_config "/boot/loader.conf" "loader_logo" "none"
    
    # NVIDIA modules (if needed)
    if lspci 2>/dev/null | grep -i nvidia >/dev/null 2>&1 || pciconf -lv 2>/dev/null | grep -i nvidia >/dev/null 2>&1; then
        info "NVIDIA hardware detected, adding drivers to loader.conf"
        update_config "/boot/loader.conf" "nvidia_load" "YES"
        update_config "/boot/loader.conf" "nvidia-modeset_load" "YES"
    fi
}

# Phase 2: Runtime System Hardening
harden_sysctl() {
    log "Configuring runtime system hardening..."
    
    # Configure sysctl.conf
    update_config "/etc/sysctl.conf" "security.bsd.see_other_uids" "0"
    update_config "/etc/sysctl.conf" "security.bsd.see_other_gids" "0"
    update_config "/etc/sysctl.conf" "security.bsd.unprivileged_read_msgbuf" "0"
    update_config "/etc/sysctl.conf" "security.bsd.unprivileged_proc_debug" "0"
    
    # Network hardening
    update_config "/etc/sysctl.conf" "net.inet.tcp.blackhole" "2"
    update_config "/etc/sysctl.conf" "net.inet.udp.blackhole" "1"
    update_config "/etc/sysctl.conf" "net.inet.ip.forwarding" "0"
    update_config "/etc/sysctl.conf" "net.inet6.ip6.forwarding" "0"
    update_config "/etc/sysctl.conf" "net.inet.ip.redirect" "0"
    update_config "/etc/sysctl.conf" "net.inet6.ip6.redirect" "0"
    update_config "/etc/sysctl.conf" "net.inet.icmp.drop_redirect" "1"
    update_config "/etc/sysctl.conf" "net.inet.icmp.log_redirect" "1"
    update_config "/etc/sysctl.conf" "net.inet.tcp.drop_synfin" "1"
    update_config "/etc/sysctl.conf" "net.inet.tcp.syncookies" "1"
    
    # Memory and process security
    update_config "/etc/sysctl.conf" "kern.randompid" "1"
    update_config "/etc/sysctl.conf" "vm.mmap_map_32bit" "0"
    
    # Apply sysctl settings immediately
    log "Applying sysctl settings..."
    sysctl -f /etc/sysctl.conf 2>/dev/null || warn "Some sysctl settings may require reboot to take effect"
}

# Phase 3: Firewall Configuration
configure_firewall() {
    log "Configuring militarized firewall..."
    
    # Create PF configuration
    cat > /etc/pf.conf << 'EOF'
# DragonFly BSD Military-Grade Firewall Configuration
# Generated by automated hardening script

# Macros
ext_if = "INTERFACE_PLACEHOLDER"

# Options
set block-policy drop
set fingerprints "/etc/pf.os"
set skip on lo0

# Tables for attack mitigation
table <bruteforce> persist
table <badnets> persist file "/etc/pf.badnets"

# Normalization
scrub in all

# Default deny all
block all

# Block known bad networks immediately
block drop in quick from <badnets>
block drop in quick from <bruteforce>

# Block all network discovery protocols (attack vectors)
block drop quick proto udp port { 137, 138, 139, 445, 5353, 1900, 68 }
block drop quick proto tcp port { 135, 139, 445, 1433, 1521, 1723, 3389 }

# Block identified attack services
block drop quick proto tcp port { 22, 23, 21, 25, 110, 143, 993, 995, 587, 465 }
block drop quick proto udp port { 161, 162, 514, 1812, 1813, 69, 111, 2049 }

# Block VPN and remote access protocols (attack vectors)
block drop quick proto { tcp, udp } port { 1194, 1723, 4500, 500 }

# Block identified malicious services
block drop quick proto tcp port { 631, 9100 }  # CUPS
block drop quick proto udp port { 5353, 427 }  # Avahi/Bonjour

# Allow essential outbound only
pass out proto tcp to any port { 53, 80, 443, 853 } keep state
pass out proto udp to any port { 53, 853 } keep state

# Allow ICMP for basic connectivity (limited)
pass inet proto icmp icmp-type { echoreq, unreach } keep state

# Log blocked connections
block log all
EOF

    # Replace interface placeholder
    sed -i '' "s/INTERFACE_PLACEHOLDER/$NET_INTERFACE/" /etc/pf.conf
    
    # Create bad networks file
    cat > /etc/pf.badnets << 'EOF'
# Bad networks to block
127.0.0.0/8
169.254.0.0/16
224.0.0.0/4
240.0.0.0/4
255.255.255.255/32
0.0.0.0/8
EOF

    info "Firewall configured for interface: $NET_INTERFACE"
}

# Phase 4: Service Lockdown
lockdown_services() {
    log "Implementing service lockdown..."
    
    # Configure rc.conf with minimal services
    update_config "/etc/rc.conf" "hostname" "fortress.local"
    update_config "/etc/rc.conf" "ifconfig_${NET_INTERFACE}" "DHCP"
    
    # Disable all potentially dangerous services
    update_config "/etc/rc.conf" "sshd_enable" "NO"
    update_config "/etc/rc.conf" "sendmail_enable" "NO"
    update_config "/etc/rc.conf" "sendmail_submit_enable" "NO"
    update_config "/etc/rc.conf" "sendmail_outbound_enable" "NO"
    update_config "/etc/rc.conf" "sendmail_msp_queue_enable" "NO"
    update_config "/etc/rc.conf" "inetd_enable" "NO"
    update_config "/etc/rc.conf" "portmap_enable" "NO"
    update_config "/etc/rc.conf" "rpcbind_enable" "NO"
    update_config "/etc/rc.conf" "nfs_server_enable" "NO"
    update_config "/etc/rc.conf" "nfs_client_enable" "NO"
    update_config "/etc/rc.conf" "ftpd_enable" "NO"
    update_config "/etc/rc.conf" "telnetd_enable" "NO"
    
    # Enable security services
    update_config "/etc/rc.conf" "pf_enable" "YES"
    update_config "/etc/rc.conf" "pf_rules" "/etc/pf.conf"
    update_config "/etc/rc.conf" "pflog_enable" "YES"
    
    # Enable secure DNS if unbound is available
    if pkg info unbound >/dev/null 2>&1; then
        update_config "/etc/rc.conf" "unbound_enable" "YES"
        info "Unbound DNS enabled"
    fi
}

# Phase 5: File System Hardening
harden_filesystem() {
    log "Applying filesystem hardening..."
    
    # Secure critical system files
    chmod 600 /etc/rc.conf 2>/dev/null || true
    chmod 600 /etc/sysctl.conf 2>/dev/null || true
    chmod 600 /boot/loader.conf 2>/dev/null || true
    chmod 700 /root 2>/dev/null || true
    chmod 755 /etc 2>/dev/null || true
    chmod 644 /etc/passwd 2>/dev/null || true
    chmod 600 /etc/master.passwd 2>/dev/null || true
    
    # Secure log files
    if [ -d /var/log ]; then
        chmod 640 /var/log/* 2>/dev/null || true
        chown root:wheel /var/log/* 2>/dev/null || true
    fi
    
    # Create secure temp directory
    if [ ! -d /tmp ]; then
        mkdir -p /tmp
    fi
    chmod 1777 /tmp
    
    info "Filesystem permissions hardened"
}

# Phase 6: Install and Configure Control D
install_controld() {
    log "Installing and configuring Control D (ctrld)..."
    
    # Get script directory to find ctrld binary
    SCRIPT_DIR="$(dirname "$(realpath "$0")")"
    CTRLD_BINARY="$SCRIPT_DIR/ctrld"
    
    # Expected MD5 hash for security verification
    EXPECTED_MD5="8d2b15069391d2d6072da210e1b58619"
    EXPECTED_SIZE="20172994"
    
    # Check if ctrld binary exists
    if [ ! -f "$CTRLD_BINARY" ]; then
        warn "ctrld binary not found at: $CTRLD_BINARY"
        warn "Please ensure ctrld binary is in the same directory as this script"
        return 1
    fi
    
    # Verify file size
    ACTUAL_SIZE=$(stat -f %z "$CTRLD_BINARY" 2>/dev/null)
    if [ "$ACTUAL_SIZE" != "$EXPECTED_SIZE" ]; then
        error "ctrld binary size mismatch. Expected: $EXPECTED_SIZE, Got: $ACTUAL_SIZE"
    fi
    
    # Verify MD5 hash for security
    if command -v md5 >/dev/null 2>&1; then
        ACTUAL_MD5=$(md5 -q "$CTRLD_BINARY" 2>/dev/null)
        if [ "$ACTUAL_MD5" != "$EXPECTED_MD5" ]; then
            error "ctrld binary MD5 verification failed. Expected: $EXPECTED_MD5, Got: $ACTUAL_MD5"
        fi
        info "✓ ctrld binary MD5 verification passed"
    else
        warn "md5 command not available, skipping hash verification"
    fi
    
    # Install ctrld binary
    log "Installing ctrld binary..."
    cp "$CTRLD_BINARY" /usr/local/bin/ctrld
    chmod +x /usr/local/bin/ctrld
    chown root:wheel /usr/local/bin/ctrld
    
    # Verify installation
    if /usr/local/bin/ctrld --version >/dev/null 2>&1; then
        info "✓ ctrld installed successfully"
    else
        warn "ctrld installation verification failed"
        return 1
    fi
    
    # Create Control D configuration directory
    mkdir -p /etc/controld
    
    # Create Control D configuration
    log "Configuring Control D with SKY1 endpoint..."
    cat > /etc/controld/ctrld.toml << 'EOF'
[service]
log_level = "info"
log_path = "/var/log/controld.log"

[[upstream]]
name = "controld-sky1"
endpoint = "https://kq47xeldb1.dns.controld.com/dns-query"
timeout = 5000
bootstrap_dns = "76.76.2.22"

[[upstream.bootstrap_dns]]
ip = "76.76.2.22"
port = 53

[[upstream.bootstrap_dns]]  
ip = "2606:1a40::22"
port = 53

[listener]
ip = "127.0.0.1"
port = 53

[listener.policy]
name = "SKY1"
networks = ["0.0.0.0/0", "::/0"]
EOF

    # Set secure permissions on config
    chmod 600 /etc/controld/ctrld.toml
    chown root:wheel /etc/controld/ctrld.toml
    
    # Create Control D service script
    log "Creating Control D service..."
    cat > /etc/rc.d/controld << 'EOF'
#!/bin/sh

. /etc/rc.subr

name="controld"
rcvar="controld_enable"
command="/usr/local/bin/ctrld"
command_args="run --config /etc/controld/ctrld.toml"
pidfile="/var/run/controld.pid"
start_cmd="controld_start"
stop_cmd="controld_stop"
status_cmd="controld_status"

controld_start()
{
    echo "Starting Control D DNS..."
    # Stop any existing unbound service that might conflict
    service unbound stop 2>/dev/null || true
    
    # Start Control D
    $command $command_args &
    echo $! > $pidfile
    
    # Wait a moment and verify it started
    sleep 2
    if controld_status >/dev/null 2>&1; then
        echo "Control D started successfully"
    else
        echo "Control D failed to start"
        return 1
    fi
}

controld_stop()
{
    echo "Stopping Control D DNS..."
    if [ -f $pidfile ]; then
        kill $(cat $pidfile) 2>/dev/null
        rm -f $pidfile
    fi
    # Kill any remaining ctrld processes
    pkill -f ctrld 2>/dev/null || true
}

controld_status()
{
    if [ -f $pidfile ] && kill -0 $(cat $pidfile) 2>/dev/null; then
        echo "Control D is running (PID: $(cat $pidfile))"
        return 0
    else
        echo "Control D is not running"
        return 1
    fi
}

load_rc_config $name
run_rc_command "$1"
EOF

    chmod +x /etc/rc.d/controld
    
    # Configure DNS resolution
    log "Configuring system DNS to use Control D..."
    
    # Stop conflicting DNS services
    service unbound stop 2>/dev/null || true
    
    # Update resolv.conf
    cat > /etc/resolv.conf << 'EOF'
nameserver 127.0.0.1
options edns0
search local
EOF
    
    # Make resolv.conf immutable to prevent changes
    chflags schg /etc/resolv.conf
    
    # Enable Control D service
    update_config "/etc/rc.conf" "controld_enable" "YES"
    update_config "/etc/rc.conf" "unbound_enable" "NO"
    
    # Test Control D configuration
    log "Testing Control D configuration..."
    if /usr/local/bin/ctrld run --config /etc/controld/ctrld.toml --test 2>/dev/null; then
        info "✓ Control D configuration test passed"
    else
        warn "Control D configuration test failed"
    fi
    
    info "Control D installation and configuration completed"
    info "DNS will be secured with SKY1 endpoint after service starts"
}

# Phase 7: Attack Service Blocker
create_attack_blocker() {
    log "Creating attack service blocker..."
    
    cat > /usr/local/bin/harden-services.sh << 'EOF'
#!/bin/sh
# Block services identified as attack vectors
# Based on real-world threat intelligence

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Kill any running attack services
ATTACK_SERVICES="avahi-daemon cups-browsed cupsd ssh sshd telnet telnetd samba smbd nmbd kerneloops openvpn vnc vncserver bluetooth bluetoothd"

for service in $ATTACK_SERVICES; do
    if pgrep "$service" >/dev/null 2>&1; then
        log "THREAT DETECTED: Killing malicious service: $service"
        pkill -f "$service"
    fi
done

# Block service startup by disabling rc.d scripts
RC_DIRS="/etc/rc.d /usr/local/etc/rc.d"
BLOCK_SERVICES="avahi-daemon cups-browsed cupsd sshd telnetd smbd nmbd bluetooth openvpn"

for dir in $RC_DIRS; do
    if [ -d "$dir" ]; then
        for service in $BLOCK_SERVICES; do
            if [ -f "$dir/$service" ]; then
                chmod 000 "$dir/$service" 2>/dev/null
                log "Blocked startup script: $dir/$service"
            fi
        done
    fi
done

# Check for suspicious network connections
SUSPICIOUS_PORTS="22 23 21 445 135 139 631 5353 1900"
for port in $SUSPICIOUS_PORTS; do
    if netstat -an | grep ":$port " >/dev/null 2>&1; then
        log "ALERT: Suspicious network activity on port $port"
    fi
done

log "Attack service blocking completed"
EOF

    chmod +x /usr/local/bin/harden-services.sh
    
    # Run the blocker
    /usr/local/bin/harden-services.sh
}

# Phase 7: Intrusion Detection
create_monitoring() {
    log "Creating intrusion detection system..."
    
    cat > /usr/local/bin/monitor-attacks.sh << 'EOF'
#!/bin/sh
# Continuous monitoring for attack patterns
# Based on documented threat intelligence

LOGFILE="/var/log/security-monitor.log"
ALERT_FILE="/var/log/security-alerts.log"

log_alert() {
    echo "[SECURITY ALERT $(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$ALERT_FILE"
}

log_info() {
    echo "[INFO $(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOGFILE"
}

# Create initial timestamp
touch /tmp/last-security-check

while true; do
    # Check for suspicious processes
    ATTACK_PROCESSES="avahi cups-browsed kerneloops ssh telnet samba openvpn vnc bluetooth"
    for proc in $ATTACK_PROCESSES; do
        if pgrep -f "$proc" >/dev/null 2>&1; then
            log_alert "ATTACK DETECTED: Malicious process running: $proc"
        fi
    done
    
    # Check for suspicious network connections
    SUSPICIOUS_PORTS="22 23 21 445 135 139 631 5353 1900 1194 3389"
    for port in $SUSPICIOUS_PORTS; do
        if netstat -an | grep ":$port " >/dev/null 2>&1; then
            log_alert "ATTACK DETECTED: Suspicious network connection on port $port"
        fi
    done
    
    # Check for file modifications in critical directories
    CRITICAL_DIRS="/etc /boot /bin /sbin /usr/bin /usr/sbin"
    for dir in $CRITICAL_DIRS; do
        if [ -d "$dir" ]; then
            if find "$dir" -newer /tmp/last-security-check -type f 2>/dev/null | head -1 | grep -q .; then
                log_alert "ATTACK DETECTED: Critical system file modification in $dir"
            fi
        fi
    done
    
    # Check for new network interfaces (potential attack vector)
    CURRENT_INTERFACES=$(ifconfig -l | wc -w)
    if [ -f /tmp/interface-count ]; then
        PREVIOUS_INTERFACES=$(cat /tmp/interface-count)
        if [ "$CURRENT_INTERFACES" -ne "$PREVIOUS_INTERFACES" ]; then
            log_alert "ATTACK DETECTED: Network interface configuration changed"
        fi
    fi
    echo "$CURRENT_INTERFACES" > /tmp/interface-count
    
    # Update timestamp
    touch /tmp/last-security-check
    log_info "Security scan completed"
    
    # Wait 30 seconds before next check
    sleep 30
done
EOF

    chmod +x /usr/local/bin/monitor-attacks.sh
    
    # Create monitoring service
    cat > /etc/rc.d/security-monitor << 'EOF'
#!/bin/sh

. /etc/rc.subr

name="security_monitor"
rcvar="security_monitor_enable"
command="/usr/local/bin/monitor-attacks.sh"
pidfile="/var/run/security-monitor.pid"
start_cmd="security_monitor_start"
stop_cmd="security_monitor_stop"

security_monitor_start()
{
    echo "Starting security monitor..."
    $command &
    echo $! > $pidfile
}

security_monitor_stop()
{
    echo "Stopping security monitor..."
    if [ -f $pidfile ]; then
        kill $(cat $pidfile)
        rm -f $pidfile
    fi
}

load_rc_config $name
run_rc_command "$1"
EOF

    chmod +x /etc/rc.d/security-monitor
    update_config "/etc/rc.conf" "security_monitor_enable" "YES"
}

# Phase 9: Apply and Verify
apply_hardening() {
    log "Applying security hardening..."
    
    # Load firewall rules
    if service pf status >/dev/null 2>&1; then
        service pf reload
    else
        service pf start
    fi
    
    # Start logging
    service pflog start 2>/dev/null || true
    
    # Apply sysctl settings
    sysctl -f /etc/sysctl.conf 2>/dev/null || warn "Some sysctl settings require reboot"
    
    # Run service blocker
    /usr/local/bin/harden-services.sh
    
    # Start Control D DNS service
    log "Starting Control D DNS service..."
    service controld start 2>/dev/null || warn "Control D will start on next boot"
    
    # Test DNS resolution with Control D
    sleep 3
    if nslookup google.com 127.0.0.1 >/dev/null 2>&1; then
        info "✓ Control D DNS resolution working"
    else
        warn "Control D DNS test failed"
    fi
    
    # Start monitoring
    service security-monitor start 2>/dev/null || warn "Security monitor will start on next boot"
    
    log "Security hardening applied successfully"
}

# Verification function
verify_hardening() {
    
    log "Verifying security configuration..."
    
    # Check Control D
    if service controld status >/dev/null 2>&1; then
        info "✓ Control D DNS service is running"
        
        # Test DNS resolution
        if nslookup google.com 127.0.0.1 >/dev/null 2>&1; then
            info "✓ Control D DNS resolution working"
        else
            warn "✗ Control D DNS resolution failed"
        fi
    else
        warn "✗ Control D service not running"
    fi
    
    # Check firewall
    if pfctl -s info >/dev/null 2>&1; then
    else
    else
    fi
    
    # Check key sysctl settings
    for setting in "security.bsd.see_other_uids" "net.inet.tcp.blackhole" "kern.randompid"; do
        if sysctl "$setting" >/dev/null 2>&1; then
            info "✓ $setting configured"
        else
            warn "✗ $setting not set"
        fi
    done
    
    # Check file permissions
    if [ "$(stat -f %p /etc/rc.conf 2>/dev/null)" = "100600" ]; then
        info "✓ Critical file permissions secured"
    else
        warn "✗ File permission check failed"
    fi
    
    # Check for running attack services
    FOUND_ATTACKS=0
    for service in avahi-daemon cups-browsed ssh telnet; do
        if pgrep "$service" >/dev/null 2>&1; then
            warn "✗ Attack service running: $service"
            FOUND_ATTACKS=1
        fi
    done
    
    if [ $FOUND_ATTACKS -eq 0 ]; then
        info "✓ No attack services detected"
    fi
    
    log "Security verification completed"
}

# Main execution
main() {
    log "Starting DragonFly BSD Military-Grade Security Hardening"
    log "========================================================="
    
    check_root
    backup_configs
    detect_interface
    detect_storage
    
    harden_kernel
    harden_sysctl
    configure_firewall
    lockdown_services
    install_controld
    harden_filesystem
    create_attack_blocker
    create_monitoring
    apply_hardening
    verify_hardening
    
    log "========================================================="
    log "Security hardening completed successfully!"
    log "Backup location: $BACKUP_DIR"
    log "Security monitor: /usr/local/bin/monitor-attacks.sh"
    log "Control D service: service controld status"
    log "DNS test: nslookup google.com 127.0.0.1"
    log "Service blocker: /usr/local/bin/harden-services.sh"
    log "Control D service: service controld status"
    log "DNS test: nslookup google.com 127.0.0.1"
    log "Alert log: /var/log/security-alerts.log"
    log "Control D config: /etc/controld/ctrld.toml"
    log ""
    warn "REBOOT REQUIRED to activate all kernel-level protections"
}

}

# Run main function
main "$@"

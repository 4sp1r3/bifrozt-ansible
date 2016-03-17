#!/usr/bin/env bash
set -e
#
#   Copyright (c) 2016, Are Hansen - Honeypot Development.
#
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without modification, are
#   permitted provided that the following conditions are met:
#
#   1. Redistributions of source code must retain the above copyright notice, this list
#   of conditions and the following disclaimer.
#
#   2. Redistributions in binary form must reproduce the above copyright notice, this
#   list of conditions and the following disclaimer in the documentation and/or other
#   materials provided with the distribution.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND AN
#   EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
#   OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
#   SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
#   INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
#   TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
#   BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
#   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY
#   WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#
#   --------------------------------------------------------------
#
#   - 0.0.3-DEV
#     * Added change log data
#     * Removing the neccesity of using 'sudo su -' by generating the Ansible SSH key in a
#       custom location and setting the 'private_key_file' in ansible.cfg.
#     * Added 'info' argument.
#     * Supressed output from various commands.
#
#   - 0.0.4-DEV
#     * ´info´ argument has been removed.
#     * Dedicated function will now generate time stamps. 
#     * Replaced hardcoded items that were used multiple times with
#       declared variables
#     * Consolidated all scripted apt-get actions into a single function.
#     * Git clone function made re-usable.
#     * Function for getting IPv4 address from interfaces made re-usable.
#     * Random DHCP network generation during setup.
#     * Random IPv4 address for the honeypot generated during setup.
#     * Chooses a random empheral port for SSH administration.
#     * Updates firewall rules with new SSH port.
#     * Script now requires the MAC address of the honeypot as an argument.
#
#   - 0.0.5
#     * Makes HonSSH configuration active.
#
#   - 0.0.6
#     * Added tests to prevent script from failing due to missing files and
#       directories.
#     * Script will begin and end with a clean up function that will purge
#       obsolete software and Git repos from the system.
#     * The script will delete itself when all functions have been executed.
#
#   - 0.0.7
#     * Colorized script output.
#     * Added some additional execution checks.
#     * Script will print post-execution steps after all setup task has
#       completed without errors.
#     * Optimized cleanup function slightly to prevent it from deleting
#       certain files and directories.
#     * Supressed output from Ansible playbook.
#     * The git_clone function can now diffirentiate between git branches.
#
#   --------------------------------------------------------------
#
#
declare version="0.0.7"
declare author="Are Hansen"
declare created="2016-02-24"
declare -rx Script="${0##*/}"
declare honssh_dir="/opt/honssh"
declare git_bzans="https://github.com/Bifrozt/bifrozt-ansible.git"
declare hs_default_cfg="$honssh_dir/honssh.cfg.default"
declare hs_active_cfg="$honssh_dir/honssh.cfg"
declare ansible_cfg="/etc/ansible/ansible.cfg"
declare setup_log="/var/log/Bifrozt_Setup.log"
declare interfaces="/etc/network/interfaces"
declare ipv4_hater="/etc/network/ipv4hater"
declare dhcpd_conf="/etc/dhcp/dhcpd.conf"
declare sshd_conf="/etc/ssh/sshd_config"
declare dst_bzans="/tmp/bifrozt-ansible"
declare bz_key="/etc/ansible/BZKEY"
declare rdb='\033[1;7;31m'
declare red='\033[1;31m'
declare grn='\033[1;32m'
declare ylw='\033[1;33m'
declare blu='\033[1;34m'
declare wht='\033[1;37m'
declare end='\033[0m'


# Nothing to see here, just a script banner.
function script_banner()
{
echo -e "

${wht}=========${end} ${grn}$Script${end} ${wht}-${end} ${grn}$version${end} ${wht}-${end} ${grn}$created${end} ${wht}-${end} ${grn}$author${end} ${wht}=========${end}

"
}


# Return time stamp and information string.
# ARG 1: Information string.
# ARG 2: Exit code.
function time_stamp()
{
    time="${wht}$(date +"%Y-%m-%d %T") -${end}"

    if [ -z "$1" ]
    then
        echo -e "$time ${wht}[${end}${rdb}FATAL${end}]${wht}: $FUNCNAME requires two arguments, one entry string and one exit code.${end}"
        exit 1
    fi

    case "$2" in
        0)
            echo -e "$time ${wht}[${end}${grn}OKAY${end}${wht}]: $1 ${end}"
            ;;
        1)
            echo -e "$time ${wht}[${end}${red}FAIL${end}${wht}]: $1 ${end}"
            exit 1
            ;;
        2)
            echo -e "$time ${wht}[${end}${ylw}INFO${end}${wht}]: $1 ${end}"
            ;;
        3)
            echo -e "$time ${wht}[${end}${blu}TASK${end}${wht}]: $1 ${end}"
            ;;
        *)
            echo -e "$time ${wht}[${end}${rdb}FATAL${end}${wht}]: $FUNCNAME will only accept 0, 1, 2 or 3 as exit codes. ${end}"
            exit 1
            ;;
    esac
}


# Verify that the distro we are using is Ubuntu
function check_distro()
{
    lsb_release -a 2>/dev/null \
    | head -n1 \
    | awk '{ print $3 }'
}


# Verify that the host has two network interface cards. Expects them to start with 'eth'.
function check_if()
{
    ifconfig -a \
    | cut -c1-4 \
    | grep -c 'eth'
}


# Returns IPv4 address of interface.
# ARG 1: Interface name.
function ipv4_if()
{
    if [ ! -z "$1" ]
    then
        ifconfig "$1" \
        | grep 'inet addr:' \
        | cut -d ':' -f2 \
        | awk '{ print $1 }'
    else
        time_stamp "$FUNCNAME did not receive any argument." "1"
        exit 1
    fi
}


# Returns the port number thats defined in the current sshd_config file.
function get_ssh_port()
{
    if [ ! -e "$sshd_conf" ]
    then
        time_stamp "$sshd_conf could not be found." "1"
    else
        grep ^'Port' "$sshd_conf" \
        | awk '{ print $2 }'
    fi
}


# Checks if the system has a previously downloaded bifrozt-ansible repo, Ansible SSH keys,
# root autorized_keys, Ansible PPA or fi Ansible is installed. Any of these items will be
# purged from the system before the setup will comence.
# The function expectes one or zero arguments.
function verify_clean()
{
    
    if [ -e "$dst_bzans" ]
    then
        time_stamp "Removing existing \"bifrozt-ansible\" repo." "3"
        rm -rf "$dst_bzans" \
        || time_stamp "Issue occured while removing old repo." "1"
        time_stamp "Existing repo was removed." "0"
    fi

    if [ -e "$bz_key" ]
    then
        time_stamp "Removing Ansible SSH keys..." "3"
        rm -rf "$bz_key" \
        || time_stamp "Encountered an issue while removing Ansible SSH keys." "1"
        time_stamp "Ansible SSH keys was removed." "0"
    fi

    if [ -e "/root/.ssh/authorized_keys" ]
    then
        time_stamp "Removing \"/root/.ssh/authorized_keys\"..." "3"
        rm "/root/.ssh/authorized_keys" \
        || time_stamp "Encountered an issue while removing \"/root/.ssh/authorized_keys\"." "1"
        time_stamp "The \"/root/.ssh/authorized_keys\" file was removed." "0"
    fi

    if [ -e "/etc/ansible" ]
    then
        time_stamp "Removing Ansible from the system..." "3"
        apt-get remove ansible -y &>/dev/null \
        || time_stamp "Failure occured while running apt-get remove ansible." "1"
        apt-get purge ansible -y &>/dev/null \
        || time_stamp "Failure occured while running apt-get purge ansible." "1"
        rm -rf "/etc/ansible" \
        || time_stamp "Failure occured when attempting to remove \"/etc/ansible\"." "1"
        time_stamp "Ansible was removed from the system." "0"
    fi

    if [ -e "/etc/apt/sources.list.d/ansible-ansible-trusty.list" ]
    then
        time_stamp "Removing Ansible PPA..." "3"
        add-apt-repository --remove ppa:ansible/ansible -y &>/dev/null \
        || time_stamp "Encountered an issue while removing Ansible PPA from the system." "1"
        rm "/etc/apt/sources.list.d/ansible-ansible-trusty.list" \
        || time_stamp "Encountered an issue while removing Ansible PPA from the system." "1"
        time_stamp "Ansible PPA was removed from the system." "0"
    fi

    case "$1" in
        startup)
            if [ -e "/etc/geoip2" ]
            then
                time_stamp "Removing \"/etc/geoip2\"..." "3"
                rm -rf "/etc/geoip2" \
                || time_stamp "Failed to remove \"/etc/geoip2\"." "1"
                time_stamp "Removed \"/etc/geoip2\"." "0"
            fi

            if [ -e "$honssh_dir" ]
            then
                time_stamp "Removing $honssh_dir..." "3"
                rm -rf "$honssh_dir" \
                || time_stamp "Issue while removing Ansible PPA from the system." "1"
                time_stamp "$honssh_dir was removed." "0"
            fi

            time_stamp "Pre-execution clean up completed." "0"
            ;;
        *)
            time_stamp "Post-execution clean up completed." "0"
            time_stamp "Setup completed." "0"    
            ;;
    esac
}


# Update system, add Ansible PPA, install ansible and configure Ansible host key checking.
function apt_get_things()
{
    time_stamp "Installing all avalible system updates..." "3"
    apt-get update &>/dev/null \
    || time_stamp "Failure occured while running apt-get update." "1"
    apt-get upgrade -y &>/dev/null \
    || time_stamp "Failure occured while running apt-get upgrade." "1"
    time_stamp "All avalible system updates have been installed." "0"

    time_stamp "Installing base dependencies..." "3"
    apt-get install software-properties-common git openssh-server -y &>/dev/null \
    || time_stamp "Failure occured while running apt-get install software-properties-common git openssh-server." "1"
    time_stamp "Base dependencies has been installed." "0"

    time_stamp "Adding Ansible PPA... " "3"
    apt-add-repository ppa:ansible/ansible -y &>/dev/null \
    || time_stamp "Failure occured while running apt-add-repository ppa:ansible/ansible." "1"
    time_stamp "Ansible PPA has been added." "0"

    time_stamp "Installing Ansible... " "3"    
    apt-get update &>/dev/null \
    || time_stamp "Failure occured while running apt-get update." "1"
    apt-get install ansible  -y &>/dev/null \
    || time_stamp "Failure occured while running apt-get install ansible." "1"
    time_stamp "Ansible has been installed." "0"

    if [ ! -e "$ansible_cfg" ]
    then
        time_stamp "$ansible_cfg was not found." "1"
    else
        time_stamp "Configuring Ansible..." "3"

        if [ ! -d "$bz_key" ]
        then
            mkdir "$bz_key" \
            || time_stamp "Failed to create $bz_key." "1"
            chmod 0700 "$bz_key" \
            || time_stamp "Failed to set permissions on $bz_key." "1"
            chown root:root "$bz_key" \
            || time_stamp "Failed to set ownership on $bz_key." "1"
        fi

        curr_str="#private_key_file = \/path\/to\/file"
        keys_str="private_key_file = \/etc\/ansible\/BZKEY\/id_rsa"

        sed -i "s/$curr_str/$keys_str/g" "$ansible_cfg" \
        || time_stamp "Failure occured when updating private_key_file location in $ansible_cfg." "1"
        sed -i 's/#host_key_checking/host_key_checking/g' "$ansible_cfg" \
        || time_stamp "Failure occured when updating host_key_checking in $ansible_cfg." "1"
        time_stamp "Ansible has been configured." "0"
    fi
}


# Clone git repo to destination.
# ARG 1: GitHub repo URL.
# ARG 2: Local path.
# ARG 3: Branch name.
function git_clone()
{
    if [ -z "$1" ]
    then
        time_stamp "Did not receive any URL." "1"
    fi

    if [ -z "$2" ]
    then
        time_stamp "Did not receive path to local destination." "1"
    fi

    time_stamp "Cloning $3 branch of Bifrozt into $2..." "3"
    git clone -b "$3" "$1" "$2" &>/dev/null \
    || time_stamp "git clone -b $3 $1 failed." "1"
    time_stamp "The $3 branch of Bifrozt has been cloned into $2." "0"
}


# Generate SSH keys for Ansible.
function gen_ssh_keys()
{
    time_stamp "Setting up Ansible SSH keys..." "3"
    ssh-keygen -f "$bz_key/id_rsa" -t rsa -N '' &>/dev/null \
    || time_stamp "Generation of Ansible SSH keys failed." "1"
    time_stamp "Generation of Ansible SSH keys completed." "0"

    if [ ! -e "$bz_key/id_rsa.pub" ]
    then
        time_stamp "$bz_key/id_rsa.pub could not be located." "1"
    fi

    if [ ! -d "/root/.ssh" ]
    then
        time_stamp "Unable to find \"/root/.ssh\", creating it now..." "3"
        mkdir "/root/.ssh" \
        || time_stamp "Failed to create \"/root/.ssh\"." "1"
        chmod 0700 "/root/.ssh" \
        || time_stamp "Failed to set permissions on \"/root/.ssh\"." "1"
        chown -R root:root "/root/.ssh" \
        || time_stamp "Failed to set ownership on \"/root/.ssh\"." "1"
        time_stamp "\"/root/.ssh\" was created." "0"
    fi

    time_stamp "Setting up authentication key for root user (will be removed later)..." "3"
    cat "$bz_key/id_rsa.pub" > "/root/.ssh/authorized_keys" \
    || time_stamp "Failed to create \"/root/.ssh/authorized_keys\"." "1"
    chmod 0600 "$bz_key/id_rsa.pub" \
    || time_stamp "Failed to set permissions on \"$bz_key/id_rsa.pub\"." "1"
    time_stamp "Authentication key for root has been created." "0"
}


# Takes two arguments to run a playbook.
# ARG 1: Absolute path to playbook.yml
# ARG 2: Absolute path to hosts file
function run_play()
{
    if [ -z "$1" ]
    then
        time_stamp "Did not receive absoloute path to playbook.yml." "1"
    fi

    if [ ! -e "$1" ]
    then
        time_stamp "\"$1\" does not appear to exist." "1"
    fi

    if [ -z "$2" ]
    then
        time_stamp "Did not receive path to Ansible host file." "1"
    fi

    if [ ! -e "$2" ]
    then
        time_stamp "\"$2\" does not appear to exist." "1"
    fi

    IPV4="$(ipv4_if eth0)"
    sed -i "s/IPv4_OR_FQDN/$IPV4/g" "$2"

    time_stamp "Executing the playbook now..." "3"
    ansible-playbook "$1" -i "$2" &>/dev/null
    ansible_exit="$?"

    if [ "$ansible_exit" = "0" ]
    then
        time_stamp "Playbook exited with: $ansible_exit" "0"
    fi

    if [ "$ansible_exit" != "0" ]
    then
        time_stamp "Playbook exited with: $ansible_exit. Investigate \"/var/log/syslog\" to troubleshoot." "1"
    fi
}


# Locates and retruns the current network name in the dhcpd.conf, excluding the last octet.
function locate_current_network()
{
    if [ ! -f "$dhcpd_conf" ]
    then
        time_stamp "$FUNCNAME was unable to locate the $dhcpd_conf file." "1"
    else
        grep ^'subnet' "$dhcpd_conf" \
        | awk '{ print $2 }' \
        | cut -d '.' -f1-3
    fi
}


# Randomly generates a new network to be used by the DHCP server and returns on of the RFC1918 types.
function gen_new_network()
{
    echo -e "$RANDOM 10.$(jot -r 1 0 255).$(jot -r 1 0 255)\n$RANDOM 172.16.$(jot -r 1 0 255)\n$RANDOM 192.168.$(jot -r 1 0 255)" \
    | sort -n \
    | awk '{ print $2 }' \
    | head -n1
}


# Replace the default DHCP network with a randomly generated one, updates both the MAC address
# of the honeypot and honssh.cfg.default, after which it makes honssh.default.cfg into honssh.cfg.
# ARG 1: MAC address of honeypot. (This is validated and passed to this function from main.) 
function setup_dhcp()
{
    curr_net="$(locate_current_network)"
    new_net="$(gen_new_network)"

    if [ "$(ipv4_if eth0 | cut -d '.' -f1-3)" = "$new_net" ]
    then
        new_net="$(gen_new_network)"
    fi

    time_stamp "Generating IPv4 address of the honeypot..." "3"

    old_honey="$curr_net.200"
    new_honey="$curr_net.$(jot -r 1 2 254)"

    sed -i "s/$old_honey/$new_honey/g" "$dhcpd_conf" \
    || time_stamp "Something went wrong while randomizing or updating the IPv4 address of the honeypot." "1"
    time_stamp "IPv4 address for the honeypot has been created." "0"

    old_mac="00:22:3f:e3:1f:bf"
    new_mac="$1"

    time_stamp "Updating the MAC address of the honeypot..." "3"
    sed -i "s/$old_mac/$new_mac/g" "$dhcpd_conf" \
    || time_stamp "Failed to update the MAC address of the honeypot." "1"
    time_stamp "MAC address of the honeypot has been updated." "0"

    time_stamp "Generating new DHCP network..." "3"
    sed -i "s/$curr_net/$new_net/g" "$dhcpd_conf" \
    || time_stamp "Failed to generate new DHCP network." "1"
    time_stamp "Network for the DHCP server has been created." "0"

    time_stamp "DHCP will be using this network: ${ylw}$new_net.0/24${end}" "2"
    new_honey_ip="$(honey_ip)"
    time_stamp "The honeypot will be assigned this IPv4 address: ${ylw}$new_honey_ip${end}" "2"

    time_stamp "Updating configuration for interface eth1..." "3"
    sed -i "s/$curr_net/$new_net/g" "$interfaces" \
    || time_stamp "Failed to update interface configuration for eth1." "1"
    time_stamp "Configuration for eth1 has been updated." "0"
    time_stamp "Restarting the eth1 interface..." "3"
    ifdown eth1 &>/dev/null
    ifup eth1 &>/dev/null \
    || time_stamp "Restart of interface eth1 failed." "1"
    time_stamp "Restart of interface eth1 completed." "0"

    eth1_ip="$(ipv4_if eth1)"
    time_stamp "IPv4 address of eth1: ${ylw}$eth1_ip${end}" "3"

    time_stamp "Restarting DHCP server..." "3"
    service isc-dhcp-server restart &>/dev/null \
    || time_stamp "DHCP server failed to restart." "1"
    time_stamp "DHCP server has been restarted." "0"

    time_stamp "Updating honssh.cfg.default..." "3"
    sed -i "s/$old_honey/$new_honey/g" "$hs_default_cfg" \
    || time_stamp "Update of honssh.cfg.default failed." "1"
    sed -i "s/$curr_net/$new_net/g" "$hs_default_cfg" \
    || time_stamp "Update of honssh.cfg.default failed." "1"
    time_stamp "Update of honssh.cfg.default completed." "0"

    time_stamp "Making active configuration file, honssh.cfg, from honssh.cfg.default..." "3"
    cp "$hs_default_cfg" "$hs_active_cfg" \
    || time_stamp "Creation of active configuration file failed." "1"
    time_stamp "Creation of active configuration file completed." "0"
}


# Chooses a new SSH port for Bifrozt administration at random.
function conf_new_ssh()
{
    if [ ! -e "$sshd_conf" ]
    then
        time_stamp "$sshd_conf was not found." "1"
    fi

    if [ ! -e "$ipv4_hater" ]
    then
        time_stamp "No firewall rule set was not found." "1"
    fi

    time_stamp "Selecting a new SSH port for Bifrozt administration..." "3"

    new_ssh_port="$(jot -r 1 49152 65535)"
    old_ssh_port="$(get_ssh_port)"

    time_stamp "Updating sshd_config..." "3"
    sed -i "s/$old_ssh_port/$new_ssh_port/g" "$sshd_conf" \
    || time_stamp "Error occured while updating $sshd_conf." "1"
    time_stamp "$sshd_conf has been updated." "0"

    new_fw_ssh="-A INPUT -i eth0 -p tcp -m tcp --dport $new_ssh_port -j ACCEPT"
    curr_fw_ssh="-A INPUT -i eth0 -p tcp -m tcp --dport $old_ssh_port -j ACCEPT"

    time_stamp "Updating firewall rules..." "3"
    sed -i "s/$curr_fw_ssh/$new_fw_ssh/g" "$ipv4_hater" \
    || time_stamp "Error occured while updating the filrewall rules." "1"
    time_stamp "Firewall rules has been updated." "0"

    time_stamp "Restarting SSH server..." "3"
    service ssh stop &>/dev/null
    service ssh start &>/dev/null \
    || time_stamp "SSH server failed to start" "1"
    time_stamp "SSH server was restarted." "0"

    time_stamp "The SSH server is now running on TCP port: ${ylw}$new_ssh_port${end}" "2"

    time_stamp "Applying new firewall rules..." "3"
    iptables-restore < "$ipv4_hater" \
    || time_stamp "The new firewall rules failed to load." "1"
    time_stamp "The new firewall rules was applied." "0"
}


# Validates MAC address. If the MAc validation fails it will terminate the script.
function check_mac()
{
    if [[ "$1" =~ ^([a-fA-F0-9]{2}:){5}[a-zA-Z0-9]{2}$ ]]
    then
        main "$1" | tee "$setup_log"
    else
        time_stamp "The MAC address you provided, \"$1\", does not appear to be valid." "1"
    fi
}


# Returns the IPv4 address from the dhcpd.conf.
function honey_ip()
{
    if [ ! -f "$dhcpd_conf" ]
    then
        time_stamp "Could not find $dhcpd_conf." "1"
    else
        grep 'fixed-address' "$dhcpd_conf" \
        | awk '{ print $2 }' \
        | cut -d ';' -f1
    fi
}


# Wrap up function.
function wrap_up()
{
    eth0_ip="$(ipv4_if eth0)"
    ssh_port="$(get_ssh_port)"

    echo -e "\n\n${red}=================================================${end}\n"
    echo -e "${wht}Post setup actions:${end}"
    echo -e "    ${wht}1) If the honeypot is running, power it off now.${end}"
    echo -e "    ${wht}2) Reboot this machine.${end}"
    echo -e "    ${wht}3) Reconnect:${end} ${ylw}ssh -l [name of user] $eth0_ip -p $ssh_port ${end}"
    echo -e "    ${wht}4) Start the honeypot.${end}"
    echo -e "    ${wht}5) Start HonSSH:${end} ${ylw}sudo honsshctrl start.${end}"
    echo -e "\n${red}=================================================${end}\n\n"

    rm "$0"
}


# Environmental checks.
function env_checks()
{
    if [ "$(id -u)" = "0" ]
    then
        time_stamp "Are we root?...${grn}Yes${end}" "0"
    else
        time_stamp "$Script must be executed as root or with root privileges." "1"
    fi

    if [ "$(check_distro)" = "Ubuntu" ]
    then
        time_stamp "Are we running Ubuntu?...${grn}Yes${end}" "0"
    else
        time_stamp "Ubuntu is required in order to run $Script." "1"
    fi

    if [ "$(check_if)" -ge "2" ]
    then
        time_stamp "Do we have two network interface cards?...${grn}Yes${end}" "0"
    else
        time_stamp "This machine has less than two network interface cards. $Script expected to find \"eth0\" and \"eth1\"." "1"
    fi
}


# Call functions and pass arguments.
function main()
{
    script_banner
    verify_clean "startup"
    env_checks
    apt_get_things
    git_clone "$git_bzans" "$dst_bzans" "master"
    gen_ssh_keys "$bz_key"
    run_play "$dst_bzans/playbook.yml" "$dst_bzans/hosts"
    setup_dhcp "$1"
    conf_new_ssh
    verify_clean
    wrap_up
}


if [ "$#" != "1" ]
then
    time_stamp "Missing argument. $Script requires the MAC address of your honeypot." "1"
else
    check_mac "$1"
fi


exit 0

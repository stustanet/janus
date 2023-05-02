#! /usr/bin/env python3
# -*- coding: utf-8 -*-
import configparser
import subprocess
import sys
from typing import List,Optional
import argparse
import ipaddress
from pathlib import Path
import struct
import socket

import ldap
from ldap.ldapobject import LDAPObject


CONFIG_PATH = Path('/etc/ssn/ssn-janus.ini')

def ip2int(addr: str) -> int:
    return struct.unpack("!I", socket.inet_aton(addr))[0]

def read_config(file_path: Path):
    config = configparser.ConfigParser()
    config.read(file_path)
    return config


def _exec_nft_cmd(args: List) -> str:
    return subprocess.run(['nft'] + args, stdout=subprocess.PIPE).stdout.decode('utf-8')

def _exec_nft_cmds_atomic(cmd: str, verbose: bool) -> str:
    nft = subprocess.Popen(
        ['nft', '-f', '-'],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    stdout, stderr = nft.communicate(cmd.encode('utf-8'))

    if verbose and stdout:
        print(stdout)

    if stderr:
        print(stderr)

def _export_cmds(cmd: str, export: Optional[str]):
    if export is not None:
        f = open(export, "w")
        f.write(cmd)
        f.close()
        print(f"nft commands written to {export}")


def connect_to_ldap(config, binddn: str, bindpw: str, verbose: bool = False) -> LDAPObject:
    if verbose:
        print('Connecting to LDAP...')

    ldap_servers = config['general']['ldap_servers'].split(',')

    for server in ldap_servers:
        conn = ldap.initialize(server)
        conn.protocol_version = ldap.VERSION3
        conn.set_option(ldap.OPT_X_TLS_CACERTDIR, '/etc/ssl/certs')
        conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_HARD)

        try:
            conn.start_tls_s()
            conn.simple_bind_s(binddn, bindpw)
            return conn
        except ldap.LDAPError as connect_error:
            conn.unbind_s()
            if verbose:
                print(f'Error contacting Server {server}: {connect_error}')

            continue

    print(f'Failed to contact any ldap server out of {config["general"]["ldap_servers"]}')

    raise ldap.LDAPError(f'Error contacting Servers {config["general"]["ldap_servers"]}')


def setup_redirects(config, binddn: str, bindpw: str, verbose: bool = False, export: Optional[str] = None) -> int:
    error = 0


    ldap_conn = connect_to_ldap(config, binddn, bindpw, verbose)

    timestamp = ldap_conn.search_s(
        binddn,
        ldap.SCOPE_SUBTREE,
        #filterstr=f'(ou=ipv4)',
        attrlist=['description']
    )[0][1]['description'][0]

    ldap_cache_dir = Path(config['general']['ldap_cache_dir'])
    ldap_cache_dir.mkdir(exist_ok=True, parents=True)

    ldap_cache_file = ldap_cache_dir / f'last_update'
    ldap_cache_file.touch(exist_ok=True)
    try:
        timestamp_local = ldap_cache_file.read_text()
    except IOError:
        timestamp_local = '0'

    if timestamp_local == timestamp:
        if verbose:
            print('Local status up to date, not running update')
        return error

    member_list = []

    ip_list = ldap_conn.search_s(binddn, ldap.SCOPE_SUBTREE, filterstr='(uid=*)', attrlist=['uid'])
    for ip in ip_list:
        try:
            net = ipaddress.ip_network(ip[1]['uid'][0].decode('utf-8'))
        except ValueError as e:
            print(f'Error {e}: invalid ip-address in LDAP: {ip}')
            error = 1
            continue
        if int(net.netmask) < 17:
            # Netzmasken kleiner als 17 sind in der StuSta nicht gueltig
            print(f'Error: range too big: {ip}')
            error = 2
            continue

        if isinstance(net, ipaddress.IPv6Network):
            print(f"Error: We don't need to support IPv6. Why should we? {net=}")
            continue


        for addr in net:
            member_list.append(str(addr))

    member_list = set(member_list)
    dorms_list = list(filter((lambda x: x != "general"), config.sections()))
    # don't always recreate IPv4Network -> cache
    dorms_ipnet = {dorm: ipaddress.IPv4Network(config[dorm]["subnet"]) for dorm in dorms_list}

    dorms_port_to_ip_map = {dorm: dict() for dorm in dorms_list}

    for address in member_list:
        matching_dorms = [dorm for dorm,net in dorms_ipnet.items() if ipaddress.IPv4Address(address) in net]
        if len(matching_dorms) != 1:
            print(f'Error: IP address {address} is in {"no" if len(matching_dorms) == 0 else "multiple"} dorms: {matching_dorms}. Not added.')
            continue
        
        dorm_name = matching_dorms[0]

        dorm_dict = dorms_port_to_ip_map[dorm_name]
        
        if bool(config[dorm_name]["new_system"]):
            # computing port number based on the IP address (3 ports per room):
            # Consider IP address in binary form: 32 digits.
            # First 15 digits is the constant prefix -- discard them
            # Last 4 digits are 16 IP addresses of one room -- omit for now.
            # We end up with 13 digits unique for every room
            # To get room number starting from 0 we subtract 2048 because
            # IP addresses on the rooms start at X.X.128.X, and not X.X.0.X
            # so room 0's 13 digits are 0.10000000.0000

            octets = [int(a) for a in str(address).split(".")]
            address_no = octets[3]&0x0F

            part1 = (octets[1]&1)<<12
            part2 = octets[2]<<4
            part3 = (octets[3]&0xF0)>>4
            room_no = ((part1|part2)|part3) - 2048
            
            port = 9999 + 3*room_no + address_no
            dorm_dict[port] = str(address)


        else:
            # Old system from before 29.04.2023 (IP-Armageddon)
            octets = str(address).split(".")
            port = 10000  +  256 * int(octets[2])  +  int(octets[3])
            dorm_dict[port] = str(address)
            



    new_ips = ','.join(member_list)
    cmd = '''
    flush chain ip nat portrelay_dnat
    flush chain ip nat portrelay_snat
    '''

    for dorm, dorm_dict in dorms_port_to_ip_map.items():

        port_to_ip_22_str = " . 22 , ".join([f"{port} : {str(ip)}" for port,ip in dorm_dict.items()]) + " . 22 "
        port_to_ip_70_str = " . 70 , ".join([f"{port} : {str(ip)}" for port,ip in dorm_dict.items()]) + " . 70 "

        mark22 = f"0x{ip2int(config[dorm]['tor22_ip']):02x}"
        mark70 = f"0x{ip2int(config[dorm]['tor70_ip']):02x}"

        cmd_part = f'''
        add map ip nat {dorm}_port_to_ip_22 {{type inet_service: ipv4_addr . inet_service ; }}
        add map ip nat {dorm}_port_to_ip_70 {{type inet_service: ipv4_addr . inet_service ; }}
        flush map ip nat {dorm}_port_to_ip_22
        flush map ip nat {dorm}_port_to_ip_70
        add element ip nat {dorm}_port_to_ip_22 {{ {port_to_ip_22_str} }}
        add element ip nat {dorm}_port_to_ip_70 {{ {port_to_ip_70_str} }}

        add rule ip nat portrelay_dnat ip daddr {config[dorm]["tor22_ip"]} mark set {mark22} dnat ip addr . port to tcp dport map @{dorm}_port_to_ip_22
        add rule ip nat portrelay_dnat ip daddr {config[dorm]["tor70_ip"]} mark set {mark70} dnat ip addr . port to tcp dport map @{dorm}_port_to_ip_70
        add rule ip nat portrelay_dnat ip daddr {config[dorm]["tor22_ip"]} ip protocol udp ct status assured mark set {mark22} dnat ip addr . port to udp dport map @{dorm}_port_to_ip_22
        add rule ip nat portrelay_dnat ip daddr {config[dorm]["tor70_ip"]} ip protocol udp ct status assured mark set {mark70} dnat ip addr . port to udp dport map @{dorm}_port_to_ip_70
        add rule ip nat portrelay_dnat ip daddr {config[dorm]["tor22_ip"]} ip protocol udp mark set {mark22} limit rate 10/second dnat ip addr . port to udp dport map @{dorm}_port_to_ip_22 
        add rule ip nat portrelay_dnat ip daddr {config[dorm]["tor70_ip"]} ip protocol udp mark set {mark70} limit rate 10/second dnat ip addr . port to udp dport map @{dorm}_port_to_ip_70 

        add rule ip nat portrelay_snat meta mark {mark22} snat to {config[dorm]["tor22_ip"]}
        add rule ip nat portrelay_snat meta mark {mark70} snat to {config[dorm]["tor70_ip"]}
        '''
        cmd = cmd + cmd_part

    _export_cmds(cmd, export)

    _exec_nft_cmds_atomic(cmd, verbose)


    if verbose:
        print('updating timestamp...')
    try:
        ldap_cache_file.write_text(timestamp.decode('utf-8'))
    except exception as e:
        print(f'error {e}: could not write timestamp to {ldap_cache_file}')
        # sys.exit(5)
        error = 5
        return error

    ldap_conn.unbind_s()
    return error

def cleanup_rules(config, verbose: bool, export: Optional[str]) -> int:
    err = 0

    if verbose:
        print("flushing chains and maps...")

    cmd = f'''
    flush chain ip nat portrelay_dnat
    flush chain ip nat portrelay_snat
    '''

    dorms_list = filter((lambda x: x != "general"), config.sections())
    for dorm in dorms_list:
        cmd_part = f'''
        flush map ip nat {dorm}_port_to_ip_22
        flush map ip nat {dorm}_port_to_ip_70
        '''

        cmd = cmd + cmd_part

    _export_cmds(cmd, export)

    _exec_nft_cmds_atomic(cmd, verbose)

    if verbose:
        print("done")



def main(verbose: bool, action: str, export: Optional[str]):
    config = read_config(CONFIG_PATH)
    err = 0
    if action in ["start", "update"]:
        err = setup_redirects(
            config,
            binddn=config['general']['ldap_binddn'],
            bindpw=config['general']['ldap_bindpw'],
            verbose=verbose, export=export)
    elif action == "stop":
        err = cleanup_rules(config, verbose=verbose, export=export)

    sys.exit(err)


def create_parser():
    parser = argparse.ArgumentParser('ssn memberfilter updater')
    parser.add_argument('-v', '--verbose', action='store_true', dest='verbose', help="Verbose output")
    parser.add_argument('-x', '--export', action='store', nargs=1, dest='export', default=[None],
                        help="takes the path where to export the firewall rules to")
    parser.add_argument('action', choices=["start", "update", "stop"], default="update", action="store",
                        help="What does the program do?")

    return parser


if __name__ == '__main__':
    args = create_parser().parse_args()
    main(verbose=args.verbose, action=args.action, export=args.export[0])

import ipaddress

def ql_bin_to_ip(ip):
    return ipaddress.ip_address(ip).compressed
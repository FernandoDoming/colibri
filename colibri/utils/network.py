import socket
import random
import ipaddress

def ql_bin_to_ip(ip):
    return ipaddress.ip_address(ip).compressed

def random_ipv4():
    n1 = random.choice(range(1, 254))
    n2 = random.choice(range(1, 254))
    n3 = random.choice(range(1, 254))
    n4 = random.choice(range(1, 254))
    return f"{n1}.{n2}.{n3}.{n4}"

def random_private_ipv4():
    n4 = random.choice(range(1, 254))
    return f"192.168.1.{n4}"
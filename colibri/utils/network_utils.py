import random
import ipaddress

def ql_bin_to_ip(ip):
    return ipaddress.ip_address(ip).compressed

def random_ipv4():
    n1 = random.choice(range(0, 255))
    n2 = random.choice(range(0, 255))
    n3 = random.choice(range(0, 255))
    n4 = random.choice(range(0, 255))
    return f"{n1}.{n2}.{n3}.{n4}"
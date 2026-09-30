import ipaddress

_INTERNAL = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
                                                 "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10")]


def is_external(ip) -> bool:
    """True for a valid address outside RFC1918/loopback/link-local.

    (ipaddress.is_private also covers documentation ranges such as 203.0.113.0/24, which are not internal.)
    """
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return not any(a in n for n in _INTERNAL if n.version == a.version)


def is_internal(ip) -> bool:
    try:
        ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return not is_external(ip)

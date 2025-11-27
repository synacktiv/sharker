from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'dhcp6-auth'
    description = 'Extract DHCPv6 authentication data'

    categories = [
        'creds',
        'dhcp6'
    ]

    pcap_filter = 'dhcpv6.option.type == 11'

    mandatory_selectors = [
        'dhcpv6.auth.realm',
        'dhcpv6.auth.key_id',
        'dhcpv6.auth.md5_data'
    ]

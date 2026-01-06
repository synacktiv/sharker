from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'dhcp6-client'
    description = 'Extract DHCPv6 client information'

    categories = [
        'dhcp6'
    ]

    pcap_filter = 'dhcpv6.msgtype == 1'  # DHCPv6 Solicit

    mandatory_selectors = [
    ]

    optional_selectors = [
        'dhcpv6.client_domain',
        'dhcpv6.tld'
    ]

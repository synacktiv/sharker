from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'rip-auth'
    description = 'Extract RIP authentication type and authentication data'

    categories = [
        'creds',
        'rip'
    ]

    pcap_filter = 'rip.auth.type'

    mandatory_selectors = [
        'rip.auth.type',
        'rip.authentication_data'
    ]

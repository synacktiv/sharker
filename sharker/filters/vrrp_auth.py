from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'vrrp-auth'
    description = 'Extract VRRP authentication data'

    categories = [
        'creds',
        'vrrp'
    ]

    pcap_filter = 'vrrp.auth_type'

    mandatory_selectors = [
        'vrrp.auth_type',
        'vrrp.md5_auth_data'
    ]

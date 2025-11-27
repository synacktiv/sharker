from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'hsrp-auth'
    description = 'Extract HSRP authentication data'

    categories = [
        'creds',
        'hsrp'
    ]

    pcap_filter = 'hsrp.auth_data'

    mandatory_selectors = [
        'hsrp.auth_data'
    ]

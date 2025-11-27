from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'tacacs-plus-auth'
    description = 'Extract TACACS+ authentication type'

    categories = [
        'creds',
        'tacacs'
    ]

    pcap_filter = 'tacplus.type == 1'

    mandatory_selectors = [
        'tacplus.type'
    ]

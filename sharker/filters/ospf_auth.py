from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'ospf-auth'
    description = 'Extract OSPF auth type and data'

    categories = [
        'creds',
        'ospf'
    ]

    pcap_filter = 'ospf.auth.type'

    mandatory_selectors = [
        'ospf.auth.type',
        'ospf.auth.crypt.seq_nbr',
        'ospf.auth.crypt.data',
        'ospf.auth.simple'
    ]

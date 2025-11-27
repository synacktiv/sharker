from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'eigrp-auth'
    description = 'Extract EIGRP authentication digest'

    categories = [
        'creds',
        'eigrp'
    ]

    pcap_filter = 'eigrp.tlv_type == 0x0002'

    mandatory_selectors = [
        'eigrp.auth.type',
        'eigrp.auth.digest'
    ]

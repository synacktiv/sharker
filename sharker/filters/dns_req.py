from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'dns-req'
    description = 'Extract the names queried with dns'

    categories = [
        'dns',
        'heavy'
    ]

    pcap_filter = 'dns'

    mandatory_selectors = [
        'dns|Queries'
    ]

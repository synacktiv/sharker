from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'mdns'
    description = 'Extract the names queried with mdns'

    categories = [
        'dns',
        'heavy'
    ]

    pcap_filter = 'mdns'

    mandatory_selectors = [
        'mdns|Queries'
    ]

from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'llmnr'
    description = 'Extract the names queried with llmnr'

    categories = [
        'dns',
        'heavy'
    ]

    pcap_filter = 'llmnr'

    mandatory_selectors = [
        'llmnr|Queries'
    ]

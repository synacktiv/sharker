from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'nbns'
    description = 'Extract the names queried with nbns'

    categories = [
        'dns',
        'heavy'
    ]

    pcap_filter = 'nbns'

    mandatory_selectors = [
        'nbns|Queries'
    ]

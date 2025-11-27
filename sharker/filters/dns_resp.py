from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'dns-resp'
    description = 'Extract DNS responses values'

    categories = [
        'dns',
        'heavy'
    ]

    pcap_filter = 'dns.resp.name'

    mandatory_selectors = [
        'dns|Answers'
    ]

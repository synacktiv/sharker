from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'imap-request'
    description = 'Extract IMAP requests'

    categories = [
        'mail',
        'imap'
    ]

    pcap_filter = 'imap.request'

    mandatory_selectors = [
        'imap.request'
    ]

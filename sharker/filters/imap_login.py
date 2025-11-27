from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'imap-login'
    description = 'Extract IMAP credentials'

    categories = [
        'creds',
        'mail',
        'imap'
    ]

    pcap_filter = 'imap.request.command == "LOGIN"'

    mandatory_selectors = [
        'imap.request.username',
        'imap.request.password'
    ]

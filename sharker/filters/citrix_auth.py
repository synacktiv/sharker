from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'citrix-auth'
    description = 'Extract CITRIX authentication credentials'

    categories = [
        'creds',
        'citrix'
    ]

    pcap_filter = 'http.authcitrix'

    mandatory_selectors = [
        'http.authcitrix.domain',
        'http.authcitrix.user',
        'http.authcitrix.password',
        'http.authcitrix.session'
    ]

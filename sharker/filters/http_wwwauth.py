from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'http-wwwauth'
    description = 'Extract HTTP WWW-Authenticate header value'

    categories = [
        'creds',
        'http'
    ]

    pcap_filter = 'http.www_authenticate'

    mandatory_selectors = [
        'http.www_authenticate'
    ]

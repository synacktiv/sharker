from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'http-auth'
    description = 'Extract HTTP authorization header'

    categories = [
        'creds',
        'http'
    ]

    pcap_filter = 'http.authorization'

    mandatory_selectors = [
        'http.host',
        'http.authorization'
    ]

    def parser(self, data):
        self.output(' '.join(data['http.authorization']))
        return 1

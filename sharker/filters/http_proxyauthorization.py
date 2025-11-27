from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'http-proxyauthorization'
    description = 'Extract HTTP Proxy-Authorization headers'

    categories = [
        'creds',
        'http'
    ]

    pcap_filter = 'http.proxy_authorization'

    mandatory_selectors = [
        'http.proxy_authorization'
    ]

    def parser(self, data):
        self.output('\n'.join([str(t) for t in data['http.proxy_authorization']]))
        return 1

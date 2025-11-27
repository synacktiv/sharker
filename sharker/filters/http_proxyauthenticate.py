from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'http-proxyauthenticate'
    description = 'Extract HTTP Proxy-Authenticate headers'

    categories = [
        'creds',
        'http'
    ]

    pcap_filter = 'http.proxy_authenticate'

    mandatory_selectors = [
        'http.proxy_authenticate'
    ]

    def parser(self, data):
        self.output('\n'.join([str(t) for t in data['http.proxy_authenticate']]))
        return 1

from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'http-uri'
    description = 'Extract HTTP URIs'

    categories = [
        'http'
    ]

    pcap_filter = 'http.request.uri'

    mandatory_selectors = [
        'http.host',
        'http.request.method',
        'http.request.uri',
        'http.request.version'
    ]

    def parser(self, data):
        nb = 0
        for host, method, uri, version in zip(data['http.host'], data['http.request.method'], data['http.request.uri'], data['http.request.version']):
            self.output(f'{host} {method} {uri} {version}')
            nb += 1
        return nb

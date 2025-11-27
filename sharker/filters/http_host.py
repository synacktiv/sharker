from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'http-host'
    description = 'Extract HTTP Host header value'

    categories = [
        'http'
    ]

    pcap_filter = 'http.host'

    mandatory_selectors = [
        'http.host'
    ]

    def parser(self, data):
        self.output('\n'.join(data['http.host']))
        return 1

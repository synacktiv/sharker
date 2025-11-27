from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'http-server'
    description = 'Extract HTTP remote server'

    categories = [
        'http',
        'heavy'
    ]

    pcap_filter = 'http.server'

    mandatory_selectors = [
        'http.server'
    ]

    def parser(self, data):
        self.output(''.join(data['http.server']))
        return 1

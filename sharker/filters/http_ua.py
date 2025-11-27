from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'http-ua'
    description = 'Extract HTTP user agents'

    categories = [
        'http'
    ]

    pcap_filter = 'http.user_agent'

    mandatory_selectors = [
        'http.user_agent'
    ]

    def parser(self, data):
        self.output('\n'.join(data['http.user_agent']))
        return len(data['http.user_agent'])

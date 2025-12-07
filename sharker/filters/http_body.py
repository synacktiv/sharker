from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'http-body'
    description = 'Extract HTTP body data'

    categories = [
        'http',
        'heavy'
    ]

    pcap_filter = 'http'

    mandatory_selectors = [
        'http.file_data'
    ]

    def parser(self, data):
        self.output_to_file(''.join(data['http.file_data']))
        return 1

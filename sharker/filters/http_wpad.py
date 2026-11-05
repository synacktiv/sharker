from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'http-wpad'
    description = 'Extract HTTP responses to /wpad.dat requests (proxy auto-config files)'

    categories = [
        'http',
        'windows'
    ]

    pcap_filter = 'http.response && http.request.uri contains "/wpad.dat"'

    mandatory_selectors = [
        'http.response',
        'http.request.uri',
        'http.request.full_uri',
        'http.file_data'
    ]

    def parser(self, data):
        nb = 0
        for uri, full_uri, body in zip(data['http.request.uri'], data['http.request.full_uri'], data['http.file_data']):
            # Packets matched by other filters' pcap_filter also end up here
            if not uri.split('?', 1)[0].lower().endswith('/wpad.dat'):
                continue
            self.output(full_uri)
            # http.file_data is a bytes field, exported by tshark as colon-separated hex
            self.output_to_file(bytes.fromhex(body.replace(':', '')))
            nb += 1
        return nb

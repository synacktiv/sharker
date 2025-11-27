from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'tls-sni'
    description = 'Extract SNI values of TLS handshakes'

    categories = [
        'tls',
        'heavy'
    ]

    pcap_filter = 'tls.handshake'

    mandatory_selectors = [
        'tls.handshake.extensions_server_name'
    ]

    def parser(self, data):
        self.output(' '.join(data['tls.handshake.extensions_server_name']))
        return len(data['tls.handshake.extensions_server_name'])

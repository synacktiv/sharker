from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'tls-cert-full'
    description = 'Extract TLS certificates'

    categories = [
        'tls',
        'heavy'
    ]

    pcap_filter = 'tls.handshake'

    mandatory_selectors = [
        'tls.handshake.certificate'
    ]

    store_in_files = True

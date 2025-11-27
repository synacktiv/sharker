from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'eap-auth'
    description = 'Extract EAP identity from EAP authentication'

    categories = [
        'creds',
        'eap'
    ]

    pcap_filter = 'eap'

    mandatory_selectors = [
        'eap.identity'
    ]

from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'ntp-mac'
    description = 'Extract MAC value of NTP authentication'

    categories = [
        'creds',
        'ntp'
    ]

    pcap_filter = 'ntp.mac'

    mandatory_selectors = [
        'ntp.mac'
    ]

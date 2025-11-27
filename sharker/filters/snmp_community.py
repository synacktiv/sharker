from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'snmp-community'
    description = 'Extract SNMP communities'

    categories = [
        'creds',
        'snmp'
    ]

    pcap_filter = 'snmp.community'

    mandatory_selectors = [
        'snmp.community'
    ]

    def parser(self, data):
        self.output(' '.join(data['snmp.community']))
        return 1

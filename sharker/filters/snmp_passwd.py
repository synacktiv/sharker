from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'snmp-passwd'
    description = 'Extract SNMP passwords'

    categories = [
        'creds',
        'snmp'
    ]

    pcap_filter = 'snmp.password'

    mandatory_selectors = [
        'snmp.password'
    ]

    def parser(self, data):
        self.output(' '.join(data['snmp.password']))
        return 1

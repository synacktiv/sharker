from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'ldap-simple'
    description = 'Extract LDAP simple bind credentials'

    categories = [
        'creds',
        'ldap'
    ]

    pcap_filter = 'ldap.simple'

    mandatory_selectors = [
        'ldap.name',
        'ldap.simple'
    ]

    def parser(self, data):
        self.output(' '.join(data['ldap.name']) + ' ' + ' '.join(data['ldap.simple']))
        return 1

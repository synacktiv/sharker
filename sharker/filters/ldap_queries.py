from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'ldap-queries'
    description = 'Extract LDAP queries'

    categories = [
        'ldap'
    ]

    pcap_filter = 'ldap.searchRequest_element'

    mandatory_selectors = [
        'ldap.searchRequest_element'
    ]

    # TODO: ideally it would be great to parse the LDAP filter ourselves and construct the resulting string
    # because right now, tshark does it, and it truncates the filter to 240 characters.

    def parser(self, data):
        res = []
        for elt in data['ldap.searchRequest_element']:
            cur = f'Base: {elt["ldap.baseObject"]}'.strip()
            for key in elt.keys():
                if key.startswith('Filter: '):
                    cur += ' | ' + key
            if 'ldap.attributes_tree' in elt:
                cur += ' | Attributes: '
                cur += ','.join(elt['ldap.attributes_tree']['ldap.AttributeDescription']) if int(elt['ldap.attributes']) > 1 else elt['ldap.attributes_tree']['ldap.AttributeDescription']
            res.append(cur)
        self.output('\n'.join(res))
        return 1

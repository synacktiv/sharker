from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'snmp-v3auth'
    description = 'Extract SNMPv3 authentication data'

    categories = [
        'creds',
        'snmp'
    ]

    pcap_filter = 'snmp.v3.auth'

    mandatory_selectors = [
        'snmp.v3.auth',
        'snmp.msgUserName'
    ]

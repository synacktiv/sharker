from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'hsrp-virt'
    description = 'Extract HSRP virtual IP address'

    categories = [
        'hsrp'
    ]

    pcap_filter = 'hsrp.virt_ip'

    mandatory_selectors = [
        'hsrp.virt_ip'
    ]

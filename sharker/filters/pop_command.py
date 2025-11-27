from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'pop-command'
    description = 'Extract POP request commands'

    categories = [
        'mail',
        'pop'
    ]

    pcap_filter = 'pop.request.command'

    mandatory_selectors = [
        'pop.request.command'
    ]

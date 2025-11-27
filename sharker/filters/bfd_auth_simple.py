from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'bfd-auth-simple'
    description = 'Extract BFD password from simple authentication'

    categories = [
        'creds',
        'bfd'
    ]

    pcap_filter = 'bfd.auth.type'

    mandatory_selectors = [
        'bfd.auth.password'
    ]

from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'bfd-auth-sh1'
    description = 'Extract BFD checksum for authentication type 5'

    categories = [
        'creds',
        'bfd'
    ]

    pcap_filter = 'bfd.auth.type == 5'

    mandatory_selectors = [
        'bfd.checksum'
    ]

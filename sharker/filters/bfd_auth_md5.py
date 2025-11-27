from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'bfd-auth-md5'
    description = 'Extract BFD checksum for authentication type 2'

    categories = [
        'creds',
        'bfd'
    ]

    pcap_filter = 'bfd.auth.type == 2'

    mandatory_selectors = [
        'bfd.checksum'
    ]

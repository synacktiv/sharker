from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'smtp-auth'
    description = 'Extract SMTP credentials'

    categories = [
        'creds',
        'smtp'
    ]

    pcap_filter = 'smtp'

    mandatory_selectors = [
        'smtp.auth.username',
        'smtp.auth.password',
        'smtp.auth.username_password'
    ]

from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'dhcp-auth'
    description = 'Extract DHCP authentication HMAC data'

    categories = [
        'creds',
        'dhcp'
    ]

    pcap_filter = 'dhcp.option.type == 90'

    mandatory_selectors = [
        'dhcp.option.dhcp_authentication.secret_id',
        'dhcp.option.dhcp_authentication.hmac_md5_hash'
    ]

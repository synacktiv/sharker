from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'ftp-command'
    description = 'Extract FTP commands and arguments'

    categories = [
        'ftp'
    ]

    pcap_filter = 'ftp.request.command'

    mandatory_selectors = [
        'ftp.request.command',
        'ftp.request.arg'
    ]

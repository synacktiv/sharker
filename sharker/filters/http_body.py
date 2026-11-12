from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'http-body'
    description = 'Extract HTTP body data'

    categories = [
        'http',
        'heavy'
    ]

    pcap_filter = 'http'

    mandatory_selectors = [
        'http.file_data'
    ]

    def parser(self, data):
        try:
            req_uri = data['http.request.full_uri'][0].split('?', maxsplit=1)[0]
            req_uri_truncated = req_uri[:150]

            req_or_res = "res" if data.get("http.response") else "req"

            idx = data['frame.number'][0]
            # We need to ensure the filename is unique, otherwise we override data
            filename = self.to_safe_filename(f"{req_uri_truncated}_{idx}_{req_or_res}")
        except Exception as e:
            self.log.warning_once('Failed to compute filename to save http body, will default to a number')
            filename = None

        # Each http.file_data item is exported by tshark as colon-separated hex
        map_http_data = map(lambda body_part: bytes.fromhex(body_part.replace(':', '')), data['http.file_data'])
        self.output_to_file(b''.join(map_http_data), filename=filename, append_to_file=False)
        return 1

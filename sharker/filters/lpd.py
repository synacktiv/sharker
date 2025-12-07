from .base import FilterConfigBase

import re
from binascii import unhexlify

r'''
Thanks to Mikeri for hints on LPD job parsing: https://github.com/mikeri/lpdshark/blob/master/lpdshark.py

If you want to convert the print job data to pdf, you can use ghostpdl.

On debian, download the latest ghostpdl sources from https://github.com/ArtifexSoftware/ghostpdl-downloads/releases .
Then, compile it:
```
$ cd ghostpdl*
$ ./configure
$ make
```

Finally, you can convert jobs using the following command:
```
perl -ne 'if ($go || /\) HP-PCL XL/) { $go=1; print; }' ./YYY_data_XXXXX | ./bin/gpcl6 -sDEVICE=pdfwrite -o output.pdf -
```
'''


class FilterConfig(FilterConfigBase):
    name = 'ldp-data'
    description = 'Line Printer Daemon data extraction'

    categories = [
        'print'
    ]

    pcap_filter = 'lpd'

    mandatory_selectors = [
        'lpd'
    ]

    safe_regex = re.compile(r'[^a-zA-Z0-9\-_.]')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # State structure:
        # {
        #   stream_id: {
        #       'mode': 'control' | 'data' | None,
        #       'filename': str,
        #       'expected_bytes': int,
        #       'received_bytes': int,
        #       'partial_header': bytes
        #   }
        # }
        self._stream_state = {}

    def _get_first(self, data, key, default=None):
        res = data.get(key)
        return res[0] if res else default

    def parser(self, data):
        # Only interested in packet sent to the printer
        if self._get_first(data, 'tcp|tcp.dstport') != '515':
            return 0

        stream_id = self._get_first(data, 'tcp|tcp.stream')
        if not stream_id:
            return 0

        # Init state for this tcp connection if needed
        if stream_id not in self._stream_state:
            self._stream_state[stream_id] = {
                'mode': None,
                'filename': None,
                'expected_bytes': 0,
                'received_bytes': 0,
                'partial_header': b''
            }

        state = self._stream_state[stream_id]

        raw_payload_hex = self._get_first(data, 'tcp|tcp.payload')
        if not raw_payload_hex:
            return 0

        new_payload = unhexlify(raw_payload_hex.replace(':', ''))

        if state['partial_header']:
            work_buffer = state['partial_header'] + new_payload
            state['partial_header'] = b''
        else:
            work_buffer = new_payload

        # Current position in the packet
        cursor = 0
        total_len = len(work_buffer)

        # We loop until we run out of data in the buffer.
        # This handles cases where one packet contains [Data] + [Null] + [Next Command]
        while cursor < total_len:

            if state['mode'] is not None:
                # We are already receiving data

                needed = state['expected_bytes'] - state['received_bytes']
                available = total_len - cursor
                chunk_size = min(needed, available)

                # Extract chunk
                chunk = work_buffer[cursor : cursor + chunk_size]

                # Write to file
                fname = f"{stream_id}_{state['filename']}"
                self.output_to_file(chunk, filename=fname)

                # Update State
                state['received_bytes'] += chunk_size
                cursor += chunk_size

                # Are we done for the current data blob?
                if state['received_bytes'] >= state['expected_bytes']:
                    # Reset state
                    state['mode'] = None
                    state['expected_bytes'] = 0
                    state['received_bytes'] = 0
                    state['filename'] = None
                    continue
                else:
                    # We ran out of data in this packet, but file is not done.
                    # Verify we are actually at the end
                    if cursor >= total_len:
                        return 1

            # No currently receiving data

            current_byte = work_buffer[cursor]

            # LPD sends 0x00 after a data file. We must skip it to find the next command.
            # We also skip 0x01 (Abort) if it appears as noise.
            if current_byte < 2:
                cursor += 1
                continue

            if current_byte in [2, 3]:  # 02 = Control, 03 = Data
                # RFC 1179: Command(1) + Count + SP + Name + LF

                remaining_view = work_buffer[cursor:]
                lf_index = remaining_view.find(b'\n')

                if lf_index != -1:
                    # Found a complete header in this buffer
                    line_end = lf_index

                    # Extract header (skip the command byte [0])
                    header_bytes = remaining_view[1:line_end]

                    try:
                        header_str = header_bytes.decode('ascii', errors='ignore')

                        # Parse: <size> <name>
                        match = re.match(r'^\s*(\d+)\s+(.*)', header_str)
                        if match:
                            size = int(match.group(1))
                            name = match.group(2).strip()
                            clean_name = self.safe_regex.sub('_', name)

                            # Set Mode
                            state['mode'] = 'control' if current_byte == 2 else 'data'
                            state['filename'] = f"{'control' if current_byte == 2 else 'data'}_{clean_name}"
                            state['expected_bytes'] = size
                            state['received_bytes'] = 0

                            cursor += (1 + len(header_bytes) + 1)

                            continue
                    except Exception:
                        self.log.warning('Got error while parsing LPD header.')
                        pass

                else:
                    # Fragmentation Detected: The buffer ends with "02 123 fil", but no \n.
                    # Save the rest of this buffer to partial_header for the next packet.
                    state['partial_header'] = work_buffer[cursor:]
                    return 1

            # Unknown byte
            # If we are here, it's not 00, 01, 02, or 03.
            # It's likely garbage or extended LPD codes we don't handle.
            # Skip it to try and resync on the next valid command.
            cursor += 1

        return 1

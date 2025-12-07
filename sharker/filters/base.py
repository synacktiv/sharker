import logging
import json
import re
import os


class FilterConfigBase:
    # Name of the filter
    name = ''

    # Short description of the filter (shown in -L)
    description = ''

    # List of categories the filter belongs to
    categories = []

    # TShark/Wireshark display filter that limits the
    # packets that will be present in the JSON temporary
    # file
    pcap_filter = ''

    # What data should be extracted from the packet and
    # given in parameter `data` of the `parser` method
    mandatory_selectors = []

    # Only used for outputing when no parse method is given
    optional_selectors = []

    # Pretty name to be displayed in the terminal output
    pretty_name = None

    # Should this filter store results in separate files
    store_in_files = False

    _last_packet_idx = 0

    _output_set = None

    _authorized_filename_rg = re.compile(r'^[a-zA-Z0-9\-_.]*$')

    def __init__(self, output_prefix, unique=False):
        self._output_prefix = output_prefix
        self._f_handles = {}

        if self.__class__.pretty_name is None:
            self.__class__.pretty_name = self.name

        if unique:
            self._output_set = set()

        self.log = LogOnceAdapter(logging.getLogger('sharker'), {'pretty_name': self.__class__.pretty_name})

    def parser(self, data):
        '''
        This method is called for each packet that matches the description in `packet_filter`.
        It should return a list when there are several results (1 per entry in the list), or a string when there is only one result.
        The length of the list, or 1 for a returned string, will be added to the summary count of the filter.
        '''
        result = {k: data[k] for k in self.mandatory_selectors if k in data}
        for optional_selector in self.optional_selectors:
            if optional_selector in data:
                result[optional_selector] = data[optional_selector]
        if self.store_in_files:
            self.output_to_file(json.dumps(result))
        else:
            self.output(json.dumps(result))
        return 1

    def output(self, data, suffix=None):
        '''
        Method to output simple data. Data will either be stored in the filter's
        file or displayed on the console (or both).

        The optional suffix parameter allows to send the data to a suffixed
        filter file. For instance, if this filter is called 'dns-req', data will
        be outputed to 'dns-req.txt' by default, if you specify a suffix, it
        will be outputed to f'dns-req-{suffix}.txt'.
        '''
        if self._output_set is not None:
            if data in self._output_set:
                return
            self._output_set.add(data)

        if self._do_log_to_console:
            self.log.info(data)
        if self._do_write_to_file:
            if self._f_handles.get(suffix) is None:

                # Verify the sanity of the suffix
                if suffix is not None and self._authorized_filename_rg.fullmatch(suffix):
                    full_output_path = f'{self._output_prefix}-{suffix}.txt'
                elif suffix is not None:
                    self.log.error(f'Suffix for file output is not authorized: {suffix}')
                    return
                else:
                    full_output_path = f'{self._output_prefix}.txt'

                self._f_handles[suffix] = open(full_output_path, 'a+', encoding='utf-8')

            self._f_handles[suffix].write(data + '\n')

    def output_to_file(self, data, filename=None):
        '''
        Method to output data to files in this filter's subfolder output.

        If the end user configures this filter to output to console, this data
        will be outputed to console instead.

        The additional filename parameter allows to specify the filename to send
        the data to, only [a-zA-Z0-9\\-_\\.] is authorized for security reasons.

        The unicity is not verified for this type of output.
        '''
        if self._do_log_to_console:
            self.log.info(data)
        if self._do_write_to_file:
            self._last_packet_idx += 1

            if filename is not None and self._authorized_filename_rg.fullmatch(filename):
                name = f'{self._output_prefix}/{filename}'
            else:
                name = f'{self._output_prefix}/{self._last_packet_idx}'

            # Create filter's output folder
            os.makedirs(self._output_prefix, exist_ok=True)

            if isinstance(data, str):
                with open(name, 'a+', encoding='utf-8') as f:
                    f.write(data)
            elif isinstance(data, bytes):
                with open(name, 'ab+') as f:
                    f.write(data)

class LogOnceAdapter(logging.LoggerAdapter):
    def __init__(self, logger, extra):
        super().__init__(logger, extra)
        self._seen_messages = set()

    def log_once(self, level, msg, *args, **kwargs):
        if msg not in self._seen_messages:
            self._seen_messages.add(msg)
            kwargs.setdefault("extra", {})
            kwargs["extra"] = {**self.extra, **kwargs["extra"]}
            self.logger.log(level, msg, *args, **kwargs)

    def debug_once(self, msg, *args, **kwargs):
        self.log_once(logging.DEBUG, msg, *args, **kwargs)

    def info_once(self, msg, *args, **kwargs):
        self.log_once(logging.INFO, msg, *args, **kwargs)

    def warning_once(self, msg, *args, **kwargs):
        self.log_once(logging.WARNING, msg, *args, **kwargs)

    def error_once(self, msg, *args, **kwargs):
        self.log_once(logging.ERROR, msg, *args, **kwargs)

    def critical_once(self, msg, *args, **kwargs):
        self.log_once(logging.CRITICAL, msg, *args, **kwargs)

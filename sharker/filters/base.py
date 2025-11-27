import logging
import json


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

    def __init__(self, output_path, unique=False):
        self._output_path = output_path
        self._f_handle = None

        if self.__class__.pretty_name is None:
            self.__class__.pretty_name = self.__class__.__module__.rsplit('.', 1)[-1]

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
        self.output(json.dumps(result))
        return 1

    def edit_logger(self, data):
        pass

    def output(self, data):
        if self._output_set is not None:
            if data in self._output_set:
                return
            self._output_set.add(data)

        if self._do_log_to_console:
            self._log_to_console(data)
        if self._do_write_to_file:
            self._output_to_file(data)

    def _log_to_console(self, data):
        self.log.info(data)

    def _output_to_file(self, data):
        if self.store_in_files:
            self._last_packet_idx += 1
            with open(f'{self._output_path}/{self._last_packet_idx}', 'w', encoding='utf-8') as f:
                f.write(data)
        else:
            if self._f_handle is None:
                self._f_handle = open(self._output_path, 'a+', encoding='utf-8')
            self._f_handle.write(data + '\n')


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

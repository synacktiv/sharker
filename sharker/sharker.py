#!/usr/bin/python3

import subprocess
import os
import importlib
import time
import pkgutil
import shutil
import logging
import rich.table
import rich.logging
import rich.highlighter
import rich.text
import rich.markup
import rich.console
import rich.json
import rich.prompt
import rich
from datetime import datetime
from click_help_colors import HelpColorsCommand

import click
from click_option_group import optgroup

import sharker.filters

console = rich.console.Console(soft_wrap=True, highlight=False)


try:
    import ijson
except ImportError:
    print('Cannot import ijson library, please install python3-ijson')
    exit(1)

FILTERS = {}

NUM_SLOTS = 10000  # This is the difference allowed between two threads
MAX_PACKET_SIZE = 10000000
TOTAL_SIZE = NUM_SLOTS * MAX_PACKET_SIZE

'''
Python3 lib requirements: python3-ijson
Tool requirements: tshark
'''


class MyRichLogHandler(logging.Handler):
    LEVEL_MAPPING = {
        logging.DEBUG: "[gray30]DEBUG[/gray30]",
        logging.INFO: "[green]INFO[/green]",
        logging.WARNING: "[yellow]WARNING[/yellow]",
        logging.ERROR: "[red]ERROR[/red]",
        logging.CRITICAL: "[bold red]CRITICAL[/bold red]",
    }

    def emit(self, record):
        msg = self.format(record)
        console.print(msg)

    def format(self, record):
        levelname = self.LEVEL_MAPPING.get(record.levelno, str(record.levelno))
        record.levelname = levelname
        record.msg = rich.markup.escape(record.msg)
        self.formatter.datefmt = f'[cyan]{self.formatter.datefmt}[/cyan]'

        return super().format(record)


def setup_logging(verbose: bool, no_color: bool):
    '''Configure the logging mechanism for sharker.'''
    log_level = logging.DEBUG if verbose else logging.INFO

    logger = logging.getLogger('sharker')
    logger.setLevel(log_level)
    logger.propagate = False

    if no_color:
        console_handler = logging.StreamHandler()
        formatter = logging.Formatter('[%(asctime)s][%(levelname)s][%(pretty_name)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    else:
        console_handler = MyRichLogHandler()
        formatter = logging.Formatter('\\[%(asctime)s]\\[%(levelname)s][blue]\\[%(pretty_name)s][/blue] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)


def check_filters_format(filter_instances, filters_names):
    '''Verify filters sanity.'''
    try:
        for filter_name in filters_names:
            if filter_name not in filter_instances:
                return False, f'Filter does not exist: {filter_name}'

            try:
                temp_instance = filter_instances[filter_name]('dummy')
                description = temp_instance.description
                categories = temp_instance.categories
                pcap_filter = temp_instance.pcap_filter
                mandatory_selectors = temp_instance.mandatory_selectors
                pretty_name = temp_instance.pretty_name
                store_in_files = temp_instance.store_in_files
                parser = temp_instance.parser
            except Exception as e:
                console.print_exception(show_locals=True)

                return (
                    False,
                    f'Filter {filter_name}: Error instantiating/accessing attrs: {e}',
                )

            if type(filter_name) != str:
                return False, f'Bad filter name: {filter_name}'
            if type(description) != str:
                return False, f'Bad filter description: {description}'
            if type(categories) != list:
                return (
                    False,
                    f'Filter {filter_name}, bad categories list type: {categories}',
                )
            if any([type(t) != str for t in categories]):
                return (
                    False,
                    f'Filter {filter_name}, bad category type in categories list',
                )
            if type(pcap_filter) != str or not pcap_filter:
                return False, f'Filter {filter_name}, bad pcap filter: {pcap_filter}'
            if type(mandatory_selectors) != list:
                return (
                    False,
                    f'Filter {filter_name}, bad selectors: {mandatory_selectors}',
                )
            if any([type(t) != str for t in mandatory_selectors]):
                return (
                    False,
                    f'Filter {filter_name}, bad selectors type: {mandatory_selectors}',
                )
            if not isinstance(pretty_name, str):
                return (
                    False,
                    f'Filter {filter_name}, bad pretty_name: {pretty_name}',
                )
            if not callable(parser):
                return False, f'Filter {filter_name}, callable with bad type'
            if type(store_in_files) != bool:
                return False, f'Filter {filter_name}, bad option type'

    except Exception as e:
        return False, repr(e)

    return True, ''


def index_paths(data, parent_path=None, results=None, separator='|'):
    """
    Traverse the JSON structure once and build a dictionary mapping
    all path suffixes -> list of values.
    Optimized version: avoids repeated string joins and function call overhead.
    """
    if results is None:
        results = {}
    if parent_path is None:
        parent_path = []

    def add_suffixes(path, value):
        # Instead of repeatedly joining slices, build suffixes once
        n = len(path)
        if n == 0:
            return
        # Build suffix strings incrementally (fastest way)
        for i in range(n):
            suffix = separator.join(path[i:n])
            values = results.get(suffix)
            if values is None:
                results[suffix] = [value]
            else:
                values.append(value)

    stack = [(data, parent_path)]

    while stack:
        current, path = stack.pop()

        if isinstance(current, dict):
            for k, v in current.items():
                path.append(k)
                add_suffixes(path, v)
                if isinstance(v, (dict, list)):
                    stack.append((v, path.copy()))
                path.pop()

        elif isinstance(current, list):
            for v in current:
                if isinstance(v, (dict, list)):
                    stack.append((v, path.copy()))

    return results


def distribute_filters_to_workers(filters_list, num_workers):
    if not filters_list:
        return []
    if num_workers <= 0:
        num_workers = 1
    chunks = [[] for _ in range(num_workers)]
    for i, filter_name in enumerate(filters_list):
        chunks[i % num_workers].append(filter_name)
    return [chunk for chunk in chunks if chunk]


def _compute_filters(
    log, active_filter_instances, indexed_packet, packet_id, summary
):
    result = {}
    for filter_name, current_filter_instance in active_filter_instances.items():
        ok = False
        for selector in current_filter_instance.mandatory_selectors:
            if selector not in indexed_packet:
                break
        else:
            ok = True
        if not ok:
            continue

        try:
            output = current_filter_instance.parser(indexed_packet)
            if output is None:
                log.warning(f'Filter {filter_name} returned None, should have returned the number of results, considering 1.')
                output = 1
            summary[filter_name] += output
        except Exception:
            log.exception('Unhandled error in filter, we should never end up here.')
            continue

    return result


def _prepare_filter_instances(filter_instances, assigned_filters, output_prefix_str, unique):
    log = logging.LoggerAdapter(logging.getLogger('sharker.preparefilter'), {'pretty_name': 'Filter setup'})
    active_filter_instances = {}
    worker_process_summary = {}
    for filter_name in assigned_filters:
        if filter_name in filter_instances:
            try:
                output_prefix = f'{output_prefix_str}{filter_name}'
                active_filter_instances[filter_name] = filter_instances[filter_name](output_prefix, unique)
                worker_process_summary[filter_name] = 0
            except Exception as e:
                console.print_exception(show_locals=True)
                log.error(
                    f'Process: Error instantiating filter "{filter_name}": {e}. Skipped by worker.'
                )
        else:
            log.error(
                f'Process: Filter "{filter_name}" (assigned) not in global FILTERS. Skipped by worker.'
            )
    return worker_process_summary, active_filter_instances


def run_tshark(filter, pcap=None, interface=None):
    log = logging.LoggerAdapter(logging.getLogger('sharker.tshark'), {'pretty_name': 'tshark'})

    if not shutil.which('tshark'):
        raise RuntimeError('tshark command not found in PATH.')

    if pcap and interface:
        raise ValueError('Cannot start tshark on both an interface and a PCAP.')

    cmd = ['tshark']
    if pcap:
        cmd += ['-r', pcap]
    if interface:
        cmd += ['-i', interface]
    cmd += [
        '-Y', filter,
        '-T', 'json', '--no-duplicate-keys',
    ]

    log.debug(f'Running {cmd}')
    try:
        tshark_proc = subprocess.Popen(
            cmd,
            shell=False,
            encoding=None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError:
        log.error('tshark not found.')
        return {}
    except UnicodeDecodeError as e:
        log.error(f'Error while decoding tshark output: {e}')
        return {}

    return tshark_proc


def parse(filter_instances, output_directory, queried_filters, threads, pcap_file=None, interface=None, output_prefix=None, unique=False, develop=False):
    log = logging.LoggerAdapter(logging.getLogger('sharker.parse'), {'pretty_name': 'sharker'})
    start_time = time.time()
    summary = {}

    if output_prefix is None:
        if pcap_file:
            base_pcap_name = os.path.basename(pcap_file)
            output_prefix = f'{base_pcap_name}-'
        elif interface:
            output_prefix = f'{interface}_{datetime.now().strftime("%Y-%m-%d_%H:%M:%S")}-'
    output_path_prefix = os.path.normpath(f'{output_directory}/{output_prefix}')

    if len(queried_filters) == 0:
        return {}

    tshark_filter_parts = [
        filter_instances[f_name].pcap_filter
        for f_name in queried_filters
        if f_name in filter_instances and hasattr(filter_instances[f_name], 'pcap_filter')
    ]
    if not tshark_filter_parts:
        log.critical(f'No valid tshark filter parts for {pcap_file if pcap_file else interface}. Not running tshark.')
        return {}
    big_filter = '(' + ') || ('.join(tshark_filter_parts) + ')'

    tshark_proc = run_tshark(big_filter, pcap=pcap_file, interface=interface)

    if threads == 0:
        # Run in a single thread
        (
            worker_process_summary,
            active_filter_instances,
        ) = _prepare_filter_instances(filter_instances, queried_filters, output_path_prefix, unique)

        processed_packet_count = 0

        for item in ijson.items(
            tshark_proc.stdout,
            'item._source.layers',
            # use_float=True,
            # buf_size=131072,
        ):
            processed_packet_count += 1
            if processed_packet_count % 5000 == 0:
                log.info(f'Parsed {processed_packet_count//1000}k packets')
            if not isinstance(item, dict):
                log.error(f'Skipping non-dict item {processed_packet_count - 1}')
                continue

            indexed_packet = index_paths(item)
            if develop:
                rich.prompt.Prompt.ask('ready?')
                with console.pager():
                    console.print(rich.json.JSON.from_data(indexed_packet))

            _compute_filters(
                log,
                active_filter_instances,
                indexed_packet,
                processed_packet_count - 1,
                worker_process_summary,
            )

        if processed_packet_count == 0:
            log.debug('No items to process from input data.')

        summary = worker_process_summary

    finish_time = time.time()
    if summary:
        log.info(f'Finished parsing {pcap_file if pcap_file else interface} in {int(finish_time - start_time)}s')
    else:
        log.info(
            f'Finished parsing {pcap_file if pcap_file else interface} in {int(finish_time - start_time)}s, no results from filters.'
        )

    return summary


@click.command(
    cls=HelpColorsCommand,
    help='Sharker: A reasonably fast network protocol analysis tool with extensible filters.',
    context_settings=dict(help_option_names=['-h', '--help']),
    help_headers_color=None,
    help_options_color=None,
    help_options_custom_colors={'--unique': 'cyan', '--all': 'cyan', '--fast': 'green'}
)
@click.argument(
    'pcap_files',
    metavar='[PCAP[ PCAP[ ...]]',
    nargs=-1,
    type=click.Path(exists=True, dir_okay=False, resolve_path=True)
)
# Input
@optgroup.group('Input Source')
@optgroup.option(
    '-d', '--pcap-dir',
    type=click.Path(exists=True, file_okay=False, resolve_path=True),
    metavar='DIR',
    help='Path to a directory containing PCAP files to parse.'
)
@optgroup.option(
    '-i', '--interface',
    metavar='IFACE',
    help='Network interface to capture live data from (e.g., eth0, wlan0).'
)
# Output
@optgroup.group('Output Handling', help='By default, everything is written to file, and only creds category is printed to console. For very large PCAPs, advised to disable console output or at least colors, since it slows down the parsing.')
@optgroup.option('-m', '--output-mode', type=click.Choice(['file', 'console', 'both', 'develop']), help='Which output mode to enable.', default='both', show_default=True)
@optgroup.option('-u', '--unique', is_flag=True, help='Output only unique results, will gradually take more and more RAM.')
@optgroup.option('-F', '--fast', is_flag=True, help='Fastest configuration (do not affect filter selection).')
@optgroup.group('Output file mode')
@optgroup.option('-o', '--output-dir', default='./sharker_out', type=click.Path(file_okay=False), metavar='DIR', help='Output directory.')
@optgroup.option('-op', '--output-prefix', metavar='NAME', help='Prefix to use for the output files, defaults to the PCAP/interface name.')
@optgroup.group('Output console mode')
@optgroup.option('-P', 'print_everything', is_flag=True, help='Send all filters to console (default in console output mode).')
@optgroup.option('-C', 'no_color', is_flag=True, help='Do not use colors in console output, will speed up sharker when lot of stuff is printed.')
@optgroup.option('-pf', metavar='FILT[,FILT[...]]', help='Send specific filters output to console.', default='NOTSET')
@optgroup.option('-xpf', metavar='FILT[,FILT[...]]', help='Do not send specific filters to console.', default='NOTSET')
@optgroup.option('-pc', metavar='CAT[,CAT[...]]', help='Send specific filter categories to console.', default='NOTSET')
@optgroup.option('-xpc', metavar='CAT[,CAT[...]]', help='Do not send specific categories to console.', default='NOTSET')
@optgroup.option('-nwf', metavar='FILT[,FILT[...]]', help='Do not write filters output to file.', default='NOTSET')
@optgroup.option('-nwc', metavar='CAT[,CAT[...]]', help='Do not write filter categories to file.', default='NOTSET')
# Filter selection
@optgroup.group('Filter Selection')
@optgroup.option('-A', '--all', 'all_filters', is_flag=True, help='Enable all filters, will be slower.', default=False)
@optgroup.option('-f', '--filters', metavar='FILT[,FILT[...]]', help='Only run specified filters.', default='NOTSET')
@optgroup.option('-nf', '--not-filters', metavar='FILT[,FILT[...]]', help='Exclude specified filters.', default='NOTSET')
@optgroup.option('-c', '--categories', metavar='CAT[,CAT[...]]', help='Only run specified categories of filters.', default='NOTSET')
@optgroup.option('-nc', '--not-categories', metavar='CAT[,CAT[...]]', help='Exclude specified categories of filters.', default='NOTSET')
# Filter information
@optgroup.group('Filter Information')
@optgroup.option('-l', '--list-filters', is_flag=True, help='List filters that would be active with current filtering options.')
@optgroup.option('-L', '--list-all-filters', is_flag=True, help='List all available filters.')
@optgroup.option('-Lc', '--list-all-filter-categories', is_flag=True, help='List all available filter categories.')
# Performance and development
@optgroup.group('Debugging')
@optgroup.option('-t', '--threads', metavar='NB', type=int, default=0, help='EXPERIMENTAL: number of threads, use only if you know what you are doing.', hidden=True)
@optgroup.option('-v', '--verbose', is_flag=True, help='Verbose mode.')
def sharker_cli(pcap_files, pcap_dir, interface,  # Input
                output_mode, unique, fast,  # General output options
                output_dir, output_prefix,  # Output to file
                print_everything, no_color, pf, xpf, pc, xpc, nwf, nwc,  # Output to console
                all_filters, filters, not_filters, categories, not_categories,  # Filter selection
                list_filters, list_all_filters, list_all_filter_categories,  # Filter information
                threads, verbose):  # Performance

    # 1) Configure logging
    setup_logging(verbose, no_color)
    log = logging.LoggerAdapter(logging.getLogger('sharker.main'), {'pretty_name': 'sharker'})

    # 2) Check parameters
    #     - Input
    nb_inputs = (1 if pcap_files else 0) + (1 if pcap_dir else 0) + (1 if interface else 0)
    if nb_inputs == 0 and not list_filters and not list_all_filters:
        ctx = click.get_current_context()
        click.echo(ctx.get_help())
        ctx.exit('\n\nError: Must provide an input source: either PCAP files, a PCAP directory (-d), or an interface (-i).')
    elif nb_inputs > 1:
        raise click.UsageError('PCAP files, PCAP directory (-d), and interface (-i) are mutually exclusive.')

    #     - Filters selection
    # Check if the all filter selection is set
    if all_filters and any([t != 'NOTSET' for t in (filters, not_filters, categories, not_categories)]):
        raise click.UsageError('Error: --all and filter selection (-f, -nf, -c, -nc) are mutually exclusive.')
    # If nothing is set, default behavior is to not include heavy queries
    if (filters, not_filters, categories, not_categories) == (
        'NOTSET',
        'NOTSET',
        'NOTSET',
        'NOTSET',
    ) and not all_filters:
        not_categories = 'heavy'

    #     - Fast output
    if fast and (any([t != 'NOTSET' for t in (pf, pc, xpf, xpc, nwf, nwc)]) or output_mode != 'both' or print_everything or no_color):
        raise click.UsageError('Error: --fast and output handling options (--output-mode, -pf, -pc, -xpf, -xpc, -nwf, -nwc, -P, -C) are mutually exclusive.')

    # 3) Configure default values (should be the most permissive)
    if filters == 'NOTSET':
        filters = 'ALL'
    if not_filters == 'NOTSET':
        not_filters = 'NONE'
    if categories == 'NOTSET':
        categories = 'ALL'
    if not_categories == 'NOTSET':
        not_categories = 'NONE'

    #     - Output handling
    if fast:
        output_mode = 'file'
    elif (pf, pc, xpf, xpc) == ('NOTSET', 'NOTSET', 'NOTSET', 'NOTSET'):
        pc = 'creds'

    pf = [] if pf == 'NOTSET' else pf.split(',')
    pc = [] if pc == 'NOTSET' else pc.split(',')
    xpf = [] if xpf == 'NOTSET' else xpf.split(',')
    xpc = [] if xpc == 'NOTSET' else xpc.split(',')
    nwf = [] if nwf == 'NOTSET' else nwf.split(',')
    nwc = [] if nwc == 'NOTSET' else nwc.split(',')

    # 4) Gather all filter classes
    FILTERS = {}
    package = sharker.filters
    for _, module_name, is_pkg in pkgutil.iter_modules(package.__path__):
        if not is_pkg and not module_name == 'base':
            full_module_name = f"{package.__name__}.{module_name}"
            module = importlib.import_module(full_module_name)
            curclass = module.FilterConfig
            if curclass.name in FILTERS:
                log.error(f'Found two filters with same name: {curclass.name}')
                exit(1)
            FILTERS[curclass.name] = curclass

    # 5) Retrieve the list of filters wanted by the user
    queried_filters = parse_queried_filters(FILTERS, filters, categories, not_filters, not_categories)

    # 6) Ensure queried filter are in the proper format
    ok, errors = check_filters_format(FILTERS, queried_filters)
    if not ok:
        log.critical(f'Filters not properly formatted: {errors}')
        return

    # 7) Special commands that terminate sharker
    if list_all_filters:
        table = rich.table.Table(show_header=True, box=rich.box.SIMPLE)
        table.add_column('Name')
        table.add_column('Description')
        for name, obj in FILTERS.items():
            table.add_row(name, obj.description)
        rich.print(table)
        return

    if list_all_filter_categories:
        table = rich.table.Table(show_header=True, box=rich.box.SIMPLE)
        table.add_column('Name')
        cat = set()
        for filter_cls in FILTERS.values():
            for cur_cat in filter_cls.categories:
                cat.add(cur_cat)
        for name in sorted(cat):
            table.add_row(name)
        rich.print(table)
        return

    if not len(queried_filters):
        log.critical('No filter matched your requirements, you can find the list of filters with -L.')
        return

    if list_filters:
        table = rich.table.Table(show_header=True, box=rich.box.SIMPLE)
        table.add_column('Name')
        table.add_column('Description')
        for cur_filter in queried_filters:
            table.add_row(cur_filter, FILTERS[cur_filter].description)
        rich.print(table)
        return

    log.debug(f'Loaded following filters: {",".join(queried_filters)}')

    # 8) Handle output
    anything_stored_to_file = False
    for filter_name in queried_filters:
        if output_mode == 'develop':
            FILTERS[filter_name]._do_write_to_file = False
            FILTERS[filter_name]._do_log_to_console = True
            continue

        # Write to file
        if output_mode == 'file'\
                or (
                    output_mode == 'both'
                    and filter_name not in nwf
                    and all([c not in nwc for c in FILTERS[filter_name].categories])
                ):
            anything_stored_to_file = True
            FILTERS[filter_name]._do_write_to_file = True
        else:
            # Do not write these filters to file
            FILTERS[filter_name]._do_write_to_file = False

        # Log to console
        if output_mode == 'console'\
                or (
                    output_mode == 'both'
                    and (print_everything
                         or filter_name in pf
                         or any([c in pc for c in FILTERS[filter_name].categories]))
                    and filter_name not in xpf
                    and all([c not in xpc for c in FILTERS[filter_name].categories])
                ):
            FILTERS[filter_name]._do_log_to_console = True
        else:
            FILTERS[filter_name]._do_log_to_console = False

    if anything_stored_to_file:
        # Prepare output directory
        if os.path.exists(output_dir):
            if not os.path.isdir(output_dir):
                log.critical('Output directory exists but is not a directory.')
                return
        else:
            try:
                os.makedirs(output_dir)
                log.info(f'Output directory created: {output_dir}')
            except Exception as e:
                log.critical(f'An error occured while creating the output directory: {e}')
                return

    more_help = ''
    grand_total_summary = {}

    # 9) Start working
    #     - Got a folder containing PCAPs: we just build the pcap_files list
    if pcap_dir:
        pcap_files = list(pcap_files)
        for root, _, files in os.walk(pcap_dir):
            pcap_files += [os.path.join(root, t) for t in files]
        log.info(f'Found {len(pcap_files)} files.')
    #     - Got a list of PCAPs
    for pcap_path in pcap_files:
        if not os.path.isfile(pcap_path):
            log.error(f'PCAP not found: {pcap_path}. Skipping.')
            continue
        log.info(f'Processing PCAP: {pcap_path}')
        try:
            summary = parse(
                FILTERS, pcap_file=pcap_path, output_directory=output_dir, queried_filters=queried_filters, threads=threads, unique=unique, develop=output_mode == 'develop'
            )
        except Exception as e:
            if verbose:
                console.print_exception(show_locals=True)
            else:
                log.critical(f'Got error while parsing {pcap_path}: {e}')
            return
        for name, count in summary.items():
            if count == 0:
                continue
            grand_total_summary[name] = grand_total_summary.get(name, 0) + count
    #     - Got a network interface
    if interface:
        try:
            summary = parse(FILTERS, interface=interface, output_directory=output_dir, queried_filters=queried_filters, threads=threads, unique=unique, develop=output_mode == 'develop')
        except Exception as e:
            if verbose:
                console.print_exception(show_locals=True)
            else:
                log.critical(f'Got error while working on interface {interface}: {e}')
            return
        if all(t == 0 for t in summary.values()):
            more_help = 'Are you running sharker/tshark with sufficient privileges?'
        for name, count in summary.items():
            if count == 0:
                continue
            grand_total_summary[name] = grand_total_summary.get(name, 0) + count

    # 10) Work finished, handle results
    if grand_total_summary:
        log.info('Got following results.')
        table = rich.table.Table()
        table.add_column('Filter')
        table.add_column('Nb results')
        for name, count in sorted(
            grand_total_summary.items(), key=lambda x: (-x[1], x[0])
        ):
            if count == 0:
                continue
            table.add_row(name, str(count))
        rich.print(table)
        log.info(f'Results written to {os.path.abspath(output_dir)}' + more_help)
    else:
        log.warning('No results generated... ' + more_help)


def parse_queried_filters(filter_instances, filters, categories, not_filters, not_categories):
    queried_filters = []

    accepted_filters = filters.split(',')
    accepted_categories = categories.split(',')
    rejected_filters = not_filters.split(',')
    rejected_categories = not_categories.split(',')

    for filter_name, filter_data in filter_instances.items():
        # Check filter name matching
        if (filters != 'ALL' and filter_name not in accepted_filters) or (
            not_filters != 'NONE' and filter_name in rejected_filters
        ):
            continue
        if (
            categories != 'ALL'
            and all(i not in accepted_categories for i in filter_data.categories)
        ) or (
            not_categories != 'NONE'
            and any(i in rejected_categories for i in filter_data.categories)
        ):
            continue

        # This is a filter we'll apply
        queried_filters.append(filter_name)
    return queried_filters

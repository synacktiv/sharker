# Sharker: where Wireshark ends, we begin

Sharker is a powerful and extensible tool for extracting valuable data from PCAP files or from live interfaces. It leverages the power of `tshark` to efficiently parse network captures and applies a flexible filtering system to pinpoint and extract juicy information.

## Key Features

- **Extensible Filtering:** Create Python-based filters to extract any data from network packets.
- **Powerful Filtering Engine:** Selectively enable or disable filters and filter categories to fine-tune and speed up your analysis.
- **Multiple Input Sources:** Analyze `.pcap` files, directories of captures, or even live network traffic from an interface.
- **Flexible Output:** Save results to organized text files, print to the console, or both.

## Requirements

- **tshark:** The command-line companion to Wireshark is essential. You can typically install it through your system's package manager (e.g., `apt-get install tshark`, `brew install wireshark`).
- **Python 3**
- **Python libraries:** The required libraries are listed in `requirements.txt` and can be installed with `pip`/`pipx`.

## Installation

You can install Sharker using `pipx` (recommended) or a standard `pip` and `venv` environment.

### Using `pipx` (Recommended)

```bash
# Install from this repository
pipx install git+https://github.com/synacktiv/sharker.git

# Verify the installation
sharker -h
```

### Using `pip` and `venv`

```bash
# Clone the repository
git clone https://github.com/synacktiv/sharker.git
cd sharker

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Sharker
pip install .

# Verify the installation
sharker -h
```

## Usage

The basic syntax for Sharker is:

```bash
sharker [OPTIONS] [PCAP_FILE(s)]
```

### Common Options

#### Main options

| Option                       | Description                                                                                             |
| ---------------------------- | ------------------------------------------------------------------------------------------------------- |
| `-i, --interface <IFACE>`    | Capture live traffic from a network interface (e.g., `eth0`).                                           |
| `-d, --pcap-dir <DIR>`       | Analyze all PCAP files in a directory.                                                                  |
| `-o, --output-dir <DIR>`     | Specify the directory for output files (default: `./sharker_out`).                                      |
| `-m, --output-mode <MODE>`   | Set the output mode: `file`, `console`, `both`, or `develop` (default: `both`).                         |
| `-u, --unique`               | Output only unique results.                                                                             |
| `-F, --fast`                 | Fastest configuration (do not affect filter selection).                                                 |
| `-A, --all`                  | Enable all filters, will be slower.                                                                     |

#### Filtering options

| Option                       | Description                                                                                                |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `-c, --categories <CATS>`    | A comma-separated list of filter categories to run (e.g., `creds,http`).                                   |
| `-nc, --not-categories <CATS>` | A comma-separated list of filter categories to exclude (e.g., `heavy`). By default, `heavy` is excluded. |
| `-f, --filters <FILTERS>`    | A comma-separated list of specific filters to run.                                                         |
| `-nf, --not-filters <FILTERS>` | A comma-separated list of specific filters to exclude.                                                   |
| `-L, --list-all-filters`     | Display a list of all available filters and their descriptions.                                            |
| `-Lc, --list-all-filter-categories` | Display a list of all available filter categories.                                                  |
| `-l, --list-filters`         | Show the filters that will be active with the current command-line options.                                |
| `-v, --verbose`              | Enable verbose logging for debugging.                                                                      |

### Example Usage

**1. Analyze a single PCAP and save the results:**

```bash
sharker my_capture.pcap
```
*This will run all filters except those in the `heavy` category and save the output to the `sharker_out/` directory. Filters in the `creds` category will also be printed to stdout.*

**2. Apply all filters and try to go as fast as possible:**

```bash
sharker -A -F my_captures.pcap
```
*This will apply all filters and output everything to files, no results will be printed on the console.*

**3. Analyze a directory of PCAPs, focusing on credentials:**

```bash
sharker -d /path/to/pcaps -c creds
```
*This command processes all PCAP files in the specified directory, but only runs the filters in the `creds` category.*

**4. Capture live traffic and print HTTP-related information to the console:**

```bash
sudo sharker -i eth0 -c http -m console
```
*This will capture traffic from the `eth0` interface, run only the `http` category filters, and print all results directly to the terminal.*

**5. List all available filters:**

```bash
sharker -L
```

### Help output

<details>
<summary>Click to see full help output</summary>

```bash
$ sharker -h
Usage: sharker [OPTIONS] [PCAP[ PCAP[ ...]]

  Sharker: A reasonably fast network protocol analysis tool with extensible
  filters.

Options:
  Input Source:
    -d, --pcap-dir DIR            Path to a directory containing PCAP files to
                                  parse.
    -i, --interface IFACE         Network interface to capture live data from
                                  (e.g., eth0, wlan0).
  Output Handling:                By default, everything is written to file,
                                  and only creds category is printed to
                                  console. For very large PCAPs, advised to
                                  disable console output or at least colors,
                                  since it slows down the parsing.
    -m, --output-mode [file|console|both|develop]
                                  Which output mode to enable.  [default:
                                  both]
    -u, --unique                  Output only unique results, will gradually
                                  take more and more RAM.
    -F, --fast                    Fastest configuration (do not affect filter
                                  selection).
  Output file mode:
    -o, --output-dir DIR          Output directory.
    -op, --output-prefix NAME     Prefix to use for the output files, defaults
                                  to the PCAP/interface name.
  Output console mode:
    -P                            Send all filters to console (default in
                                  console output mode).
    -C                            Do not use colors in console output, will
                                  speed up sharker when lot of stuff is
                                  printed.
    -pf FILT[,FILT[...]]          Send specific filters output to console.
    -xpf FILT[,FILT[...]]         Do not send specific filters to console.
    -pc CAT[,CAT[...]]            Send specific filter categories to console.
    -xpc CAT[,CAT[...]]           Do not send specific categories to console.
    -nwf FILT[,FILT[...]]         Do not write filters output to file.
    -nwc CAT[,CAT[...]]           Do not write filter categories to file.
  Filter Selection:
    -A, --all                     Enable all filters, will be slower.
    -f, --filters FILT[,FILT[...]]
                                  Only run specified filters.
    -nf, --not-filters FILT[,FILT[...]]
                                  Exclude specified filters.
    -c, --categories CAT[,CAT[...]]
                                  Only run specified categories of filters.
    -nc, --not-categories CAT[,CAT[...]]
                                  Exclude specified categories of filters.
  Filter Information:
    -l, --list-filters            List filters that would be active with
                                  current filtering options.
    -L, --list-all-filters        List all available filters.
    -Lc, --list-all-filter-categories
                                  List all available filter categories.
  Debugging:
    -v, --verbose                 Verbose mode.
  -h, --help                      Show this message and exit.
```

</details>

## The Filter System

Sharker's power comes from its filters, located in the `sharker/filters/` directory. Each filter is a Python class that defines:

- **`name`**: A unique name for the filter.
- **`description`**: A brief explanation of what the filter does.
- **`pcap_filter`**: A `tshark` display filter to select relevant packets for this filter.
- **`categories`**: A list of categories the filter belongs to (e.g., `creds`, `dns`, `http`). `heavy` can be used for filters that will match lots of packets or perform slow operations.
- **`mandatory_selectors` and `optional_selectors`**: Keys to look for in the packet's JSON representation to identify the data of interest. Sharker will use these attributes to output data if no `parser` function is defined in the filter.
- **`parser()`**: A function that processes the packet data and returns the extracted information.

By default, Sharker runs all filters except those in the `heavy` category. You can customize this behavior with the `-c`, `-nc`, `-f`, and `-nf` options.

<details>
<summary>Click to see NTLM hashes extraction example</summary>

```python
from .base import FilterConfigBase


class FilterConfig(FilterConfigBase):
    name = 'ntlmssp'
    description = 'Extract Net-NTLM hashes for cracking purposes'

    categories = [
        'creds',
        'windows'
    ]

    pcap_filter = 'gss-api || ntlmssp'

    mandatory_selectors = [
        'ntlmssp'
    ]

    def __init__(self, *args, **kwargs):
        self.challenges = {}
        super().__init__(*args, **kwargs)

    def parser(self, data):
        tcp_conn = data['tcp.stream'][0]
        msg_type = int(data['ntlmssp.messagetype'][0], 16) if 'ntlmssp.messagetype' in data else 0

        if msg_type == 1:
            # NTLM NEGOTIATE: nothing to do
            pass
        elif msg_type == 2:
            # NTLM CHALLENGE
            self.challenges[tcp_conn] = data['ntlmssp.ntlmserverchallenge'][0].replace(':', '')
        elif msg_type == 3:
            if tcp_conn not in self.challenges:
                self.log.error('Found an NTLM message type 3 (AUTH), but no type 2 (CHALLENGE) was received beforehand -> check in pcap if the challenge was not sent in an unsupported by tshark manner from the server, like in a Proxy-Authenticate HTTP header.')
                return 0

            ntresp = data['ntlmssp.auth.ntresponse'][0].replace(':', '')
            lmresp = data['ntlmssp.auth.lmresponse'][0].replace(':', '')
            user = data['ntlmssp.auth.username'][0]
            domain = data['ntlmssp.auth.domain'][0]
            workstation = data['ntlmssp.auth.hostname'][0]

            ntlm_hash = ''
            if len(ntresp) == 24 * 2:
                # NTLMv1 response
                if domain != '':
                    ntlm_hash = f'{user}::{domain}:{lmresp}:{ntresp}:{self.challenges[tcp_conn]}'
                else:
                    ntlm_hash = f'{user}::{workstation}:{lmresp}:{ntresp}:{self.challenges[tcp_conn]}'
            else:
                # NTLMv2 response
                if domain != '':
                    ntlm_hash = f'{user}::{domain}:{self.challenges[tcp_conn]}:{ntresp[:32]}:{ntresp[32:]}'
                else:
                    ntlm_hash = f'{user}::{workstation}:{self.challenges[tcp_conn]}:{ntresp[:32]}:{ntresp[32:]}'

            del self.challenges[tcp_conn]
            self.output(ntlm_hash)
            return 1

        return 0
```

</details>

## Development

If you want to contribute to Sharker or develop your own filters, you can set up a development environment.

```bash
# Clone the repository
git clone https://github.com/synacktiv/sharker.git
cd sharker

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install in editable mode
pip install -e .

# Now you can run sharker and your changes will be reflected immediately
sharker -h
```

### Creating a New Filter

1. Create a new Python file in the `sharker/filters/` directory.
2. In that file, create a class that inherits from `FilterConfigBase` (defined in `sharker/filters/base.py`).
3. Define the required attributes (`name`, `description`, `pcap_filter`, etc.).
4. Implement the `parser()` method to extract the data you need.
	- Call the `self.output` method with the data to output.
5. Sharker will automatically discover and load your new filter.

## Inspiration & References

This project was inspired by the work of the following really nice open-source projects:

- [PCredz](https://github.com/lgandx/PCredz)
- [CredSLayer](https://github.com/ShellCode33/CredSLayer)
- [Wireshark captures](https://wiki.wireshark.org/SampleCaptures)

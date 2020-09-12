# pcap-extractor

Extracts plaintext hostnames from pcap captures and dumps them to CSV files.

## Compiling

 1. Install PcapPlusPlus to `/s/PcapPlusPlus` (or otherwise change the path in Makefile and CMakeLists.txt)
 2. `make` (or compile with cmake if that's your thing)

## Usage

    main [-hv] -f input_file -T tls_output -H http_output -D dns_output

where the output files are CSV files that will be appended to (and created, if they do not exist).

## Output format

DNS and TLS: `timestamp;mac;hostname;port`

HTTP: `timestamp;mac;hostname`

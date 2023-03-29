# PCAP CSV log generator

## Use

This tool recieves a PCAP and several input parameters and stores output in CSV format to the file specified as OUTPUT, as follows:

positional arguments:
  inputfile             Input PCAP filename.

optional arguments:
  * -h, --help // show this help message and exit
  * -o OUTPUT, --output OUTPUT // Output CSV filename.
  * -t TARGET_START_TIME, --target-start-time TARGET_START_TIME // Date and time of initial event.
  * -n, --no-response // Ignore response.
  * -s, --syn-only // Filter out all TCP packets that do not establish a connection. This will ignore all TCP packets that have combinations of flags different than SYN.
  * -r REPLACE_IP [REPLACE_IP ...], --replace-ip REPLACE_IP [REPLACE_IP ...] // Specify IP address replacement. Can specify either individual addresses, such as 10.0.1.10:192.168.1.10, or ranges of IP addresses with subnet bits, such as 10.0.1.0:192.168.1.0/24. Multiple pairs can be replaced using multiple -r args.
  * -i IGNORE_IP [IGNORE_IP ...], --ignore-ip IGNORE_IP [IGNORE_IP ...] // Specify IP address or range to ignore. Can specify either individual addresses, ranges such as 10.0.1.15-10.0.1.255, or subnets, such as 10.0.1.0/24.

## Examples

```console
$ python3 ./src/generate-log.py ./data/sample.pcap --output ./data/sample.csv --target-start-time 2022-05-09T16:27:05.966627 -r 192.168.65.0:192.168.1.0/24 -r 10.0.2.15:192.168.2.15 -r 10.0.2.3:192.168.2.3
```

This example opens sample.pcap and stores results into sample.csv. Timestamp of the first record is set to 2022-05-09T16:27:05.966627 and all other records are pushed in time accordingly. In adittion, IP addresses are replaced as follows:
* IP addresses from IP subnet 192.168.65.0/24 are replaced with corresponding addresses from IP subnet 192.168.1.0/24
* IP address 10.0.2.15 is replaced with IP address 192.168.2.15
* IP address 10.0.2.3 is replaced with IP address 192.168.2.3

```console
$ python3 ./src/generate-log.py ./data/sample.pcap --output ./data/sample-ignored.csv --target-start-time 2022-05-09T16:27:05.966627 -r 192.168.65.0:192.168.1.0/24 -r 10.0.2.15:192.168.2.15 -r 10.0.2.3:192.168.2.3 -i 10.0.2.2 -i 192.168.65.1-192.168.65.30 -i 192.168.65.35-192.168.65.254
```

This example performs the same operations as the previous, with the distinction that it also ignores a part of the communication. Concretely, communications involving the following IP addresses will not be added into the CSV log:
* IP address 10.0.2.2
* IP adresses between address 192.168.65.1 and address 192.168.65.30
* IP adresses between address 192.168.65.35 and address 192.168.65.254

```console
$ python3 ./src/generate-log.py ./data/sample.pcap --output ./data/sample-ignored.csv --target-start-time 2022-05-09T16:27:05.966627 -r 192.168.65.0:192.168.1.0/24 -r 10.0.2.15:192.168.2.15 -r 10.0.2.3:192.168.2.3 -i 10.0.2.2 -i 192.168.65.1-192.168.65.30 -i 192.168.65.35-192.168.65.254 -n
```

In addition to performing all of the operations from the precious example, this example also ignores response packets. For example, if A performs a ping over B, and then B responds to the ping, only the first packet will appear in the generated CSV log.

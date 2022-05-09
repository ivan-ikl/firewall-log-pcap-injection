import argparse
from datetime import datetime

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Cyber landscape generator')
    parser.add_argument('inputfile', help='Input PCAP filename.', type=str)
    parser.add_argument(
        '-o', '--output', help='Output CSV filename.', type=str)
    parser.add_argument(
        '-r', '--replace-ip', nargs='+', help=(
            'Specify IP address replacement. Can specify either individual '
            + 'addresses, such as 10.0.1.10:192.168.1.10, or ranges of IP '
            + 'addresses, such as 10.0.1.0/24:192.168.1.0/24. '
            + 'Multiple pairs can be replaced using '
        ), action='append', type=str, required=True)
    parser.add_argument(
        '-t', '--target-start-time', help='Date and time of initial event.',
        type=datetime, required=True)
    args = vars(parser.parse_args())

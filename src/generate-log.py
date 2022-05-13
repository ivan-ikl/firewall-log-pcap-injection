import argparse
import pcapkit
import ipaddress
import csv
from datetime import datetime, timedelta
from typing import List, Tuple, Set


class PacketProcessor:

    def __init__(self) -> None:
        pass
        self._ip_replacements={}

    def replace_ip(
            self,
            ip: str,
            replacements: List[Tuple[str, str, int]]
            ) -> str:
        if ip not in self._ip_replacements:
            for old_subnet, new_subnet in replacements:
                if ip == old_subnet and "/" not in new_subnet:
                    self._ip_replacements[ip] = new_subnet
                    break
                else:
                    addr = ipaddress.ip_address(ip)
                    src_subnet = ipaddress.ip_network(old_subnet)
                    if addr in src_subnet:
                        # addr in in src_subnet, replace with dst_subnet
                        dst_subnet = ipaddress.ip_network(new_subnet)
                        new_packed_addr = bytes([
                            a & b | c & d for a, b, c, d in zip(
                                addr.packed,
                                src_subnet.hostmask.packed,
                                dst_subnet.network_address.packed,
                                dst_subnet.netmask.packed)
                        ])
                        new_addr = ipaddress.ip_address(new_packed_addr)
                        self._ip_replacements[ip] = new_addr.exploded
                        break
        return self._ip_replacements[ip] if ip in self._ip_replacements else ip

    def process_packet_records(
            self,
            source: List[dict],
            replacements: List[Tuple[str, str, int]],
            ignored_ip_addresses: Set[str],
            ignored_ip_ranges: List[Tuple[str, str]],
            ignored_ip_subnets: List[str],
            time_shift: timedelta,
            filter_response: bool) -> List[dict]:
        new_records = []
        awaiting_response = set()
        for record in source:
            src_ignored = self.is_ip_ignored(
                record["Source IP"], ignored_ip_addresses, ignored_ip_ranges,
                ignored_ip_subnets)
            dst_ignored = self.is_ip_ignored(
                record["Destination IP"], ignored_ip_addresses,
                ignored_ip_ranges, ignored_ip_subnets)
            if not src_ignored and not dst_ignored:
                src_ip = self.replace_ip(record["Source IP"], replacements)
                src_port = record["Source Port"]
                dst_ip = self.replace_ip(record["Destination IP"], replacements)
                dst_port = record["Destination Port"]
                new_record = {
                    "Timestamp": record["Timestamp"] + time_shift,
                    "Source IP": src_ip,
                    "Source Port": src_port,
                    "Destination IP": dst_ip,
                    "Destination Port": dst_port,
                    "Protokol": record["Protokol"]
                }
                if filter_response:
                    # TODO: Present implementation is very naive, aim to
                    # develop a better response recongintion in the future
                    packet = (
                        src_ip, src_port, dst_ip, dst_port, record["Protokol"])
                    inverse = (
                        dst_ip, dst_port, src_ip, src_port, record["Protokol"])
                    if inverse in awaiting_response:
                        awaiting_response.remove(inverse)
                    else:
                        awaiting_response.add(packet)
                        new_records.append(new_record)
                else:
                    new_records.append(new_record)
        return new_records

    @staticmethod
    def is_ip_ignored(
            ip_address: str,
            ignored_ip_addresses: Set[str],
            ignored_ip_ranges: List[Tuple[str, str]],
            ignored_ip_subnets: List[str]) -> bool:
        ip = ipaddress.ip_address(ip_address)
        return (
            ip_address in ignored_ip_addresses
            or [
                1 for subnet in ignored_ip_subnets
                if ip in ipaddress.ip_network(subnet)
            ]
            or [
                1 for start, end in ignored_ip_ranges
                if (
                    int(ip) >= int(ipaddress.IPv4Address(start))
                    and int(ip) <= int(ipaddress.IPv4Address(end))
                )
            ]
        )


def parse_pcap(inputfile: str) -> List[dict]:
    extraction = pcapkit.extract(fin=inputfile, nofile=True)
    records = []
    for frame in extraction.frame:
        is_TCP = frame.info.protocols.startswith('Ethernet:IPv4:TCP')
        is_UDP = frame.info.protocols.startswith('Ethernet:IPv4:UDP')
        is_ICMP = (
            frame.info.protocols.startswith('Ethernet:IPv4:Raw')
            and frame.payload.payload.protocol == 1)
        if is_TCP or is_UDP:
            record = {
                "Timestamp": frame.info.time,
                "Source IP": frame.payload.payload.src.exploded,
                "Source Port": (
                    frame.payload.payload.payload.src if hasattr(
                        frame.payload.payload.payload, "src"
                    )
                    else frame.payload.payload.payload.srcport if hasattr(
                        frame.payload.payload.payload, "srcport"
                    ) else ""
                ),
                "Destination IP": frame.payload.payload.dst.exploded,
                "Destination Port": (
                    frame.payload.payload.payload.dst if hasattr(
                        frame.payload.payload.payload, "dst"
                    )
                    else frame.payload.payload.payload.dstport if hasattr(
                        frame.payload.payload.payload, "dstport"
                    ) else ""
                ),
                "Protokol": str(frame.payload.payload.payload.protocol).lower()
            }
            if record["Source Port"] and record["Destination Port"]:
                records.append(record)
        if is_ICMP:
            record = {
                "Timestamp": frame.info.time,
                "Source IP": frame.payload.payload.src.exploded,
                "Source Port": "",
                "Destination IP": frame.payload.payload.dst.exploded,
                "Destination Port": "",
                "Protokol": "icmp"
            }
            records.append(record)
    return records


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP CSV log generator')
    parser.add_argument('inputfile', help='Input PCAP filename.', type=str)
    parser.add_argument(
        '-o', '--output', help='Output CSV filename.', type=str, required=True)
    parser.add_argument(
        '-t', '--target-start-time', help='Date and time of initial event.',
        type=str)
    parser.add_argument(
        '-n', '--no-response', help='Ignore response.',
        const=True, default=False, action='store_const')
    parser.add_argument(
        '-r', '--replace-ip', nargs='+', help=(
            'Specify IP address replacement. Can specify either individual '
            + 'addresses, such as 10.0.1.10:192.168.1.10, or ranges of IP '
            + 'addresses with subnet bits, such as 10.0.1.0:192.168.1.0/24. '
            + 'Multiple pairs can be replaced using multiple -r args.'
        ), action='append', type=str)
    parser.add_argument(
        '-i', '--ignore-ip', nargs='+', help=(
            'Specify IP address or range to ignore. Can specify either '
            + 'individual addresses, ranges such as 10.0.1.15-10.0.1.255, '
            + 'or subnets, such as 10.0.1.0/24.'
        ), action='append', type=str)

    args = vars(parser.parse_args())

    replacements = []
    if args["replace_ip"]:
        for r in args["replace_ip"]:
            old = r[0].split(":")[0]
            new = r[0].split(":")[1]
            replacements.append((old, new))

    ignored_ip_addresses = ({
        ip[0] for ip in args["ignore_ip"]
        if "-" not in ip[0] and "/" not in ip[0]
    } if args["ignore_ip"] else set())
    ignored_ip_ranges = ([
        tuple(ip[0].split("-")) for ip in args["ignore_ip"] if "-" in ip[0]
    ] if args["ignore_ip"] else [])
    ignored_ip_subnets = ([
        ip[0] for ip in args["ignore_ip"] if "/" in ip[0]
    ] if args["ignore_ip"] else [])

    inputfile, outputfile = args["inputfile"], args["output"]
    print(f"Parsing PCAP: '{inputfile}'")
    records = parse_pcap(inputfile)

    if any(records):
        min_timestamp = records[0]["Timestamp"]
    new_time = (
        datetime.fromisoformat(args["target_start_time"])
        if args["target_start_time"] else min_timestamp)

    print("Processing records...")
    packet_processor = PacketProcessor()
    output_records = packet_processor.process_packet_records(
        records, replacements, ignored_ip_addresses, ignored_ip_ranges,
        ignored_ip_subnets, new_time - min_timestamp, args["no_response"])

    print("Storing results...")
    with open(outputfile, 'w') as f:
        w = csv.DictWriter(f, [
            "Timestamp", "Source IP", "Source Port", "Destination IP",
            "Destination Port", "Protokol"])
        w.writeheader()
        for r in output_records:
            w.writerow(r)

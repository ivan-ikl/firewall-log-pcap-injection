import argparse
import pcapkit
import ipaddress
import csv
from datetime import datetime, timedelta
from typing import Dict, List, Tuple


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
            for r in replacements:
                if ip in r[0] and r[2] == 32:
                    self._ip_replacements[ip] = r[1]
                    break
                elif r[2] < 32:
                    addr = ipaddress.ip_address(ip)
                    src_subnet = ipaddress.ip_network(f"{r[0]}/{r[2]}")
                    if addr in src_subnet:
                        # addr in in src_subnet, replace with dst_subnet
                        dst_subnet = ipaddress.ip_network(f"{r[1]}/{r[2]}")
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
        return self._ip_replacements[ip]

    def process_packet_records(
            self,
            source: List[dict],
            replacements: List[Tuple[str, str, int]],
            time_shift: timedelta) -> List[dict]:
        new_records = []
        for record in source:
            new_record = {
                "Timestamp": record["Timestamp"] + time_shift,
                "Source IP": self.replace_ip(record["Source IP"], replacements),
                "Source Port": record["Source Port"],
                "Destination IP": self.replace_ip(record["Destination IP"], replacements),
                "Destination Port": record["Destination Port"],
                "Protokol": record["Protokol"]
            }
            new_records.append(new_record)
        return new_records


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Cyber landscape generator')
    parser.add_argument('inputfile', help='Input PCAP filename.', type=str)
    parser.add_argument(
        '-o', '--output', help='Output CSV filename.', type=str)
    parser.add_argument(
        '-t', '--target-start-time', help='Date and time of initial event.',
        type=str)
    parser.add_argument(
        '-r', '--replace-ip', nargs='+', help=(
            'Specify IP address replacement. Can specify either individual '
            + 'addresses, such as 10.0.1.10:192.168.1.10, or ranges of IP '
            + 'addresses with subnet bits, such as 10.0.1.0:192.168.1.0/24. '
            + 'Multiple pairs can be replaced using multiple -r args.'
        ), action='append', type=str)

    args = vars(parser.parse_args())
    inputfile, outputfile = args["inputfile"], args["output"]
    replacements = []
    for r in args["replace_ip"]:
        old = (
            r[0].split("/")[0].split(":")[0]
            if "/" in r[0] else r[0].split(":")[0])
        new = (
            r[0].split("/")[0].split(":")[1]
            if "/" in r[0] else r[0].split(":")[1])
        bits = int(r[0].split("/")[1]) if "/" in r[0] else 32
        replacements.append((old, new, bits))

    print(f"Parsing PCAP: '{inputfile}'")
    extraction = pcapkit.extract(fin=inputfile, nofile=True)
    records = []
    for frame in extraction.frame:
        is_TCP = frame.info.protocols.startswith('Ethernet:IPv4:TCP')
        is_UDP = frame.info.protocols.startswith('Ethernet:IPv4:UDP')
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

    if any(records):
        min_timestamp = records[0]["Timestamp"]
    new_time = (
        datetime.fromisoformat(args["target_start_time"])
        if args["target_start_time"] else min_timestamp)

    print("Processing records...")
    packet_processor = PacketProcessor()
    output_records = packet_processor.process_packet_records(
        records, replacements, new_time - min_timestamp)

    print("Storing results...")
    with open(outputfile, 'w') as f:
        w = csv.DictWriter(f, [
            "Timestamp", "Source IP", "Source Port", "Destination IP",
            "Destination Port", "Protokol"])
        w.writeheader()
        for r in output_records:
            w.writerow(r)

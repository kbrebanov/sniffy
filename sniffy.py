#!/usr/bin/env python3

import argparse

import sniffer.sniffer as sniffer
import parser.packet as packet_parser

def main():
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("-i", "--interface", type=str, required=True,
                                 help='Network interface to sniff packets on')
    args = argument_parser.parse_args()

    s = sniffer.Sniffer(args.interface)
    s.start()
    try:
        for data in s.sniff():
            packet = packet_parser.Packet(data)
            if packet:
                print(packet.to_json())
    except KeyboardInterrupt:
        s.stop()
    finally:
        s.stop()

if __name__ == '__main__':
    main()

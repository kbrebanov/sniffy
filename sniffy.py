#!/usr/bin/env python3

import argparse

import sniffer.sniffer as sniffer
import parser.packet as packet_parser

def main():
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("-i", "--interface", type=str, required=True,
                                 help='Network interface to sniff packets on')
    argument_parser.add_argument("-p", "--promiscuous", required=False,
                                 action='store_true', default=False,
                                 help='Enable promiscuous mode')
    argument_parser.add_argument("-s", "--snaplen", type=int, required=False,
                                 default=sniffer.MAX_PACKET_SIZE,
                                 help='Snapshot length')
    argument_parser.add_argument("-t", "--timeout", type=int, required=False,
                                 default=sniffer.TIMEOUT,
                                 help='Read timeout in milliseconds')
    args = argument_parser.parse_args()

    promiscuous = 0
    if args.promiscuous:
        promiscuous = 1

    capture = sniffer.Sniffer(args.interface, args.snaplen, promiscuous, args.timeout)
    capture.start()
    try:
        capture.join()
    except KeyboardInterrupt:
        capture.stop()

if __name__ == '__main__':
    main()

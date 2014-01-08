#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Created by i@BlahGeek.com at 2014-01-07

import socket
import logging
import time
from ipaddr import IPAddress
from threading import Thread
from bitstring import Bits


ICMP_PROTO = socket.getprotobyname('icmp')
ICMP_ECHO_REQUEST_TYPE = 8
ICMP_TIME_EXCEED_TYPE = 11
SERVER_PORT = 2345
CLIENT_PORT = 2345
BUFSIZE = 4096
NO_RESPONSE_IP = '59.66.1.1'
UDP_HELLO_MSG = 'Hello from pypwnat'


def checksum(data, checksum_offset=1):
    ''' calcualte checksum using one's complement sum of all 16-bit words,
        put the result in the `checksum_offset`th 16-bit word
        data and returned data is bitstring.Bits'''
    chunks = list(data.cut(16))
    s = sum(map(lambda x: x.uint, chunks))
    s = (s & 0xffff) + (s >> 16)
    chunks[checksum_offset] = ~ Bits(length=16, uint=s)
    return Bits(0).join(chunks)


def make_ip_packet(src, dst, protocol, body, id=42, ttl=64):
    ip_header = Bits(hex='4500') # IP version and type of service and etc
    total_length = Bits(length=16, uint=20+body.length/8) # Total length
    # The BSD suite of platforms (excluding OpenBSD) 
    # present the IP offset and length in host byte order.
    # as they say... It's a feature, not a BUG!
    total_length = Bits(length=16, uint=socket.htons(total_length.uint))
    ip_header += total_length
    ip_header += Bits(length=16, uint=id)  # identification
    ip_header += Bits(hex='0000')  # flags, fragment offset
    ip_header += Bits(length=8, uint=ttl) # TTL
    ip_header += Bits(length=8, uint=protocol)
    ip_header += Bits(hex='0000') # checksum
    ip_header += Bits(length=32, uint=int(IPAddress(src)))
    ip_header += Bits(length=32, uint=int(IPAddress(dst)))
    return checksum(ip_header, 5) + body


def make_icmp_packet(typ, code=0, body=None, id=42, seq=42):
    icmp_header = Bits(length=8, uint=typ) # type
    icmp_header += Bits(length=8, uint=code) # code
    icmp_header += Bits(hex='0000')  # checksum
    icmp_header += Bits(length=16, uint=id) + Bits(length=16, uint=seq)
    icmp_header = checksum(icmp_header)
    return icmp_header if body is None else (icmp_header+body)


def send_echo_request(sock, ip, seq=42, id=42):
    ''' a simple ping '''
    logging.debug('Sending echo request with id=%d, seq=%d.' % (id, seq))
    icmp_packet = make_icmp_packet(ICMP_ECHO_REQUEST_TYPE)
    ip_packet = make_ip_packet(0, ip, ICMP_PROTO, icmp_packet)
    sock.sendto(ip_packet.bytes, (ip, 1))
    return ip_packet


def send_time_exceed(sock, server_ip, seq=42, id=42):
    logging.debug('Sending time exceed message.')
    inner_icmp = make_icmp_packet(ICMP_ECHO_REQUEST_TYPE)
    inner_ip = make_ip_packet(server_ip, NO_RESPONSE_IP, ICMP_PROTO, inner_icmp)
    icmp_packet = make_icmp_packet(ICMP_TIME_EXCEED_TYPE, body=inner_ip)
    ip_packet = make_ip_packet(0, server_ip, ICMP_PROTO, icmp_packet)
    sock.sendto(ip_packet.bytes, (server_ip, 1))
    return ip_packet


def handle_icmp_response(response):
    logging.debug('Handling response in new thread.')
    response = Bits(bytes=response)
    source_ip = response[12*8:][:4*8]
    source_ip = IPAddress(source_ip.uint)
    response = response[20*8:]  # ignore IP header
    typ = response[:8]
    if typ.uint != 11:
        logging.debug('Not time exceed packet, ignore.')
        return
    logging.info('Got response from %s' % source_ip.compressed)
    udpsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udpsock.bind(('0.0.0.0', SERVER_PORT))
    udpsock.connect((source_ip.compressed, CLIENT_PORT))
    udpsock.send(UDP_HELLO_MSG)


def run_server(ping_interval=10.0):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_PROTO)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sock.settimeout(ping_interval)
    while True:
        send_echo_request(sock, NO_RESPONSE_IP)
        try:
            response = sock.recv(BUFSIZE)
        except socket.timeout:
            logging.debug('No ICMP response within %f seconds, continue.' % ping_interval)
            continue
        else:
            logging.debug('Got ICMP response!')
            th = Thread(target=handle_icmp_response, args=[response])
            th.start()


def run_client(server_ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_PROTO)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    udpsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udpsock.bind(('0.0.0.0', CLIENT_PORT))
    udpsock.connect((server_ip, SERVER_PORT))
    while True:
        logging.debug('Sending hello message via UDP.')
        udpsock.send(UDP_HELLO_MSG)
        send_time_exceed(sock, server_ip, NO_RESPONSE_IP)
        try:
            response = udpsock.recv(BUFSIZE)
        except socket.error:
            logging.debug('UDP message refused, continue')
            time.sleep(0.1)
            continue
        else:
            logging.info('Got UDP response!')
            print response
            break


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG,
                        format='[%(threadName)s] %(levelname)s : %(msg)s')
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--server', action='store_true', help='Run as server')
    parser.add_argument('-c', '--client', type=str, help='Run as client, must provide IP of server')
    args = parser.parse_args()
    if args.server:
        run_server()
    else:
        run_client(args.client)

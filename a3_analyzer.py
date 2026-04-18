import struct
import sys
import math

# convert ip bytes to string = "192.168.1.1"
def bytes_to_ip(data):
    return ".".join(map(str, data))

# read all packets from pcap file and return list of (timestamp, raw_data)
def read_pcap(file_path):
    try:
        f = open(file_path, 'rb')
    except FileNotFoundError:
        print("Error: file not found: " + file_path)
        return None, None

    global_header = f.read(24)
    if len(global_header) < 24:
        print("Error: file too short to be a valid pcap")
        return None, None

    magic_number = struct.unpack('<I', global_header[0:4])[0]

    # figure out byte order and if timestamps are nanoseconds
    if magic_number == 0xa1b2c3d4:
        endian = '<'
        nano = False
    elif magic_number == 0xa1b23c4d:
        endian = '<'
        nano = True
    elif magic_number == 0xd4c3b2a1:
        endian = '>'
        nano = False
    elif magic_number == 0x4d3cb2a1:
        endian = '>'
        nano = True
    else:
        print("Error: not a valid pcap file (bad magic number)")
        return None, None

    packets = []
    first_time = None

    while True:
        packet_header = f.read(16)
        if len(packet_header) < 16:
            break

        hd = struct.unpack(endian + 'IIII', packet_header)
        ts_sec = hd[0]
        ts_usec = hd[1]
        incl_len = hd[2]

        if nano:
            pkt_time = ts_sec + ts_usec / 1000000000.0
        else:
            pkt_time = ts_sec + ts_usec / 1000000.0

        if first_time is None:
            first_time = pkt_time

        packet_data = f.read(incl_len)
        packets.append((pkt_time, packet_data))

    f.close()
    return packets, first_time


# parse IP header from packet, returns a dict fields or None
def parse_ip_header(packet_data):
    # ethernet header = 14 bytes
    if len(packet_data) < 34:
        return None

    ip_start = 14
    ip_hdr = packet_data[ip_start:ip_start + 20]

    version_ihl = ip_hdr[0]
    ip_version = (version_ihl >> 4)
    if ip_version != 4:
        return None

    ip_hdr_len = (version_ihl & 0x0F) * 4
    protocol = ip_hdr[9]
    ttl = ip_hdr[8]
    total_len = struct.unpack('>H', ip_hdr[2:4])[0]
    ip_id = struct.unpack('>H', ip_hdr[4:6])[0]
    flags_offset_field = struct.unpack('>H', ip_hdr[6:8])[0]

    # frag offset in units = 8 bytes
    frag_offset = (flags_offset_field & 0x1FFF) * 8
    mf_flag = (flags_offset_field >> 13) & 1    # more fragments
    df_flag = (flags_offset_field >> 14) & 1    # dont fragment

    src_ip = bytes_to_ip(ip_hdr[12:16])
    dst_ip = bytes_to_ip(ip_hdr[16:20])

    return {
        'hdr_len': ip_hdr_len,
        'total_len': total_len,
        'protocol': protocol,
        'ttl': ttl,
        'ip_id': ip_id,
        'frag_offset': frag_offset,
        'mf': mf_flag,
        'df': df_flag,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'ip_start': ip_start
    }


# parse ICMP header, returns dict or None
def parse_icmp(packet_data, ip_info):
    icmp_start = ip_info['ip_start'] + ip_info['hdr_len']
    if len(packet_data) < icmp_start + 8:
        return None

    icmp_type = packet_data[icmp_start]
    icmp_code = packet_data[icmp_start + 1]

    result = {
        'type': icmp_type,
        'code': icmp_code,
        'icmp_start': icmp_start
    }

    # for echo (type 8) or echo reply (type 0), then get id and sequence
    if icmp_type in (0, 8):
        if len(packet_data) >= icmp_start + 8:
            icmp_id = struct.unpack('>H', packet_data[icmp_start + 4:icmp_start + 6])[0]
            icmp_seq = struct.unpack('>H', packet_data[icmp_start + 6:icmp_start + 8])[0]
            result['icmp_id'] = icmp_id
            result['icmp_seq'] = icmp_seq

    # for TTL exceeded (type 11) or port unreachable (type 3), go thru embedded original IP
    if icmp_type in (11, 3):
        inner_ip_start = icmp_start + 8
        if len(packet_data) < inner_ip_start + 20:
            return result

        inner_ip_hdr = packet_data[inner_ip_start:inner_ip_start + 20]
        inner_hdr_len = (inner_ip_hdr[0] & 0x0F) * 4
        inner_protocol = inner_ip_hdr[9]
        inner_ttl = inner_ip_hdr[8]
        inner_id = struct.unpack('>H', inner_ip_hdr[4:6])[0]
        inner_src = bytes_to_ip(inner_ip_hdr[12:16])
        inner_dst = bytes_to_ip(inner_ip_hdr[16:20])

        result['inner_protocol'] = inner_protocol
        result['inner_id'] = inner_id
        result['inner_src'] = inner_src
        result['inner_dst'] = inner_dst

        # if embedded packet = UDP, src port for matching
        inner_udp_start = inner_ip_start + inner_hdr_len
        if inner_protocol == 17 and len(packet_data) >= inner_udp_start + 4:
            inner_sport = struct.unpack('>H', packet_data[inner_udp_start:inner_udp_start + 2])[0]
            inner_dport = struct.unpack('>H', packet_data[inner_udp_start + 2:inner_udp_start + 4])[0]
            result['inner_udp_sport'] = inner_sport
            result['inner_udp_dport'] = inner_dport

        # if embedded packet = ICMP, get seq number
        inner_icmp_start = inner_ip_start + inner_hdr_len
        if inner_protocol == 1 and len(packet_data) >= inner_icmp_start + 8:
            inner_icmp_type = packet_data[inner_icmp_start]
            inner_icmp_seq = struct.unpack('>H', packet_data[inner_icmp_start + 6:inner_icmp_start + 8])[0]
            result['inner_icmp_type'] = inner_icmp_type
            result['inner_icmp_seq'] = inner_icmp_seq

    return result


# go thru UDP header, returns dict or None
def parse_udp(packet_data, ip_info):
    udp_start = ip_info['ip_start'] + ip_info['hdr_len']
    if len(packet_data) < udp_start + 8:
        return None
    src_port = struct.unpack('>H', packet_data[udp_start:udp_start + 2])[0]
    dst_port = struct.unpack('>H', packet_data[udp_start + 2:udp_start + 4])[0]
    return {'src_port': src_port, 'dst_port': dst_port}


def analyze_traceroute(file_path):
    packets, first_time = read_pcap(file_path)
    if packets is None:
        return

    # First, figure out if this is Linux = UDP or Windows = ICMP echo traceroute

    # We look for UDP packets going to port 33434+ (Linux), otherwise or ICMP echo type 8 (Windows)
    has_traceroute_udp = False
    has_icmp_echo = False

    for (pkt_time, pkt_data) in packets:
        ip_info = parse_ip_header(pkt_data)
        if ip_info is None:
            continue

         # UDP
        if ip_info['protocol'] == 17:
            udp_info = parse_udp(pkt_data, ip_info)
            if udp_info is not None:
                if 33434 <= udp_info['dst_port'] <= 33529:
                    has_traceroute_udp = True
        # ICMP
        if ip_info['protocol'] == 1:  
            icmp_info = parse_icmp(pkt_data, ip_info)
            if icmp_info is not None and icmp_info['type'] == 8:
                has_icmp_echo = True

    is_linux = has_traceroute_udp
    is_windows = has_icmp_echo and not has_traceroute_udp

    # Then collect all relevant packets

    # We need:source packets (UDP probes or ICMP echo), ICMP TTL exceeded replies (from intermediate routers), ICMP port unreachable (type 3) or echo reply (type 0) from dest

    source_node = None
    ultimate_dest = None
    protocols_seen = set()

    # for linux, key = (timestamp, ttl, ip_id, frag_offset, packet_index)
    # for windows, key = (timestamp, ttl, packet_index)
    sent_packets = {}

    # routers that sent TTL exceeded
    ttl_exceeded_replies = []

    # destination replies=(dest_ip, match_key, timestamp)
    dest_replies = []

    # fragmentation tracking= list of fragment offsets
    frag_tracker = {}

    for idx, (pkt_time, pkt_data) in enumerate(packets):
        ip_info = parse_ip_header(pkt_data)
        if ip_info is None:
            continue

        protocols_seen.add(ip_info['protocol'])

        # track fragmentation for all outgoing packets
        if ip_info['mf'] == 1 or ip_info['frag_offset'] > 0:
            ip_id = ip_info['ip_id']
            if ip_id not in frag_tracker:
                frag_tracker[ip_id] = {'offsets': [], 'src': ip_info['src_ip'], 'dst': ip_info['dst_ip']}
            frag_tracker[ip_id]['offsets'].append(ip_info['frag_offset'])

        if is_linux and ip_info['protocol'] == 17:
            udp_info = parse_udp(pkt_data, ip_info)
            if udp_info is None:
                continue
            if 33434 <= udp_info['dst_port'] <= 33529:
                if source_node is None:
                    source_node = ip_info['src_ip']
                if ultimate_dest is None:
                    ultimate_dest = ip_info['dst_ip']

                # use source port as the match key
                match_key = udp_info['src_port']
                if match_key not in sent_packets:
                    sent_packets[match_key] = []
                sent_packets[match_key].append({
                    'time': pkt_time,
                    'ttl': ip_info['ttl'],
                    'ip_id': ip_info['ip_id'],
                    'frag_offset': ip_info['frag_offset'],
                    'src_ip': ip_info['src_ip'],
                    'dst_ip': ip_info['dst_ip'],
                    'dst_port': udp_info['dst_port']
                })

        if is_windows and ip_info['protocol'] == 1:
            icmp_info = parse_icmp(pkt_data, ip_info)
            if icmp_info is None:
                continue
            if icmp_info['type'] == 8:
                if source_node is None:
                    source_node = ip_info['src_ip']
                if ultimate_dest is None:
                    ultimate_dest = ip_info['dst_ip']

                match_key = icmp_info.get('icmp_seq', 0)
                if match_key not in sent_packets:
                    sent_packets[match_key] = []
                sent_packets[match_key].append({
                    'time': pkt_time,
                    'ttl': ip_info['ttl'],
                    'ip_id': ip_info['ip_id'],
                    'frag_offset': ip_info['frag_offset'],
                    'src_ip': ip_info['src_ip'],
                    'dst_ip': ip_info['dst_ip'],
                    'icmp_seq': icmp_info.get('icmp_seq', 0)
                })

        if ip_info['protocol'] == 1:
            icmp_info = parse_icmp(pkt_data, ip_info)
            if icmp_info is None:
                continue

            # TTL exceeded (type 11)
            if icmp_info['type'] == 11:
                router_ip = ip_info['src_ip']
                match_key = None

                if is_linux and 'inner_udp_sport' in icmp_info:
                    match_key = icmp_info['inner_udp_sport']

                if is_windows and 'inner_icmp_seq' in icmp_info:
                    match_key = icmp_info['inner_icmp_seq']

                if match_key is not None:
                    ttl_exceeded_replies.append({
                        'router_ip': router_ip,
                        'match_key': match_key,
                        'time': pkt_time
                    })

            # Port unreachable (type 3) from destination
            if is_linux and icmp_info['type'] == 3:
                dest_ip = ip_info['src_ip']
                # try to get the udp src port from embedded packet
                match_key = None
                if 'inner_udp_sport' in icmp_info:
                    match_key = icmp_info['inner_udp_sport']
                dest_replies.append({
                    'dest_ip': dest_ip,
                    'match_key': match_key,
                    'time': pkt_time
                })

            # Echo reply (type 0) from destination=Windows
            if is_windows and icmp_info['type'] == 0:
                dest_ip = ip_info['src_ip']
                match_key = icmp_info.get('icmp_seq', None)
                dest_replies.append({
                    'dest_ip': dest_ip,
                    'match_key': match_key,
                    'time': pkt_time
                })

    # Then, Figure out the hops in order

    # Build a map from match_key -> ttl of the probe
    match_key_to_ttl = {}
    for mk, pkt_list in sent_packets.items():
        # all packets with same match key should have same TTL (one probe per key)
        if pkt_list:
            match_key_to_ttl[mk] = pkt_list[0]['ttl']

    # Build a list of (ttl_value, router_ip) pairs, then sort by ttl and appearance order
    # Use a dict: ttl -> list of routers seen (in order they appear in file)
    ttl_to_routers = {}
    for reply in ttl_exceeded_replies:
        mk = reply['match_key']
        if mk in match_key_to_ttl:
            ttl_val = match_key_to_ttl[mk]
            if ttl_val not in ttl_to_routers:
                ttl_to_routers[ttl_val] = []
            router_ip = reply['router_ip']
            if router_ip not in ttl_to_routers[ttl_val]:
                ttl_to_routers[ttl_val].append(router_ip)

    # sort TTL values and build ordered list of intermediate routers
    sorted_ttls = sorted(ttl_to_routers.keys())
    intermediate_routers = []  # list of (ttl, router_ip)
    for ttl_val in sorted_ttls:
        for rip in ttl_to_routers[ttl_val]:
            intermediate_routers.append((ttl_val, rip))

    # figure out ultimate destination from destination replies
    if dest_replies:
        ultimate_dest_actual = dest_replies[0]['dest_ip']
    else:
        ultimate_dest_actual = ultimate_dest

    #Protocol field values
    proto_names = {1: 'ICMP', 17: 'UDP'}
    relevant_protocols = set()
    for p in protocols_seen:
        if p in proto_names:
            relevant_protocols.add(p)

    #Fragmentation info

    # We need to find fragments of the traceroute probes specifically
    # Only track fragments from the source node going to the destination
    traceroute_frags = {} 

    for idx, (pkt_time, pkt_data) in enumerate(packets):
        ip_info = parse_ip_header(pkt_data)
        if ip_info is None:
            continue

        # only care about packets from source to destination
        if ip_info['src_ip'] != source_node:
            continue

        if ip_info['mf'] == 1 or ip_info['frag_offset'] > 0:
            ip_id = ip_info['ip_id']
            if ip_id not in traceroute_frags:
                traceroute_frags[ip_id] = {'offsets': [], 'max_offset': 0}
            if ip_info['frag_offset'] not in traceroute_frags[ip_id]['offsets']:
                traceroute_frags[ip_id]['offsets'].append(ip_info['frag_offset'])
                if ip_info['frag_offset'] > traceroute_frags[ip_id]['max_offset']:
                    traceroute_frags[ip_id]['max_offset'] = ip_info['frag_offset']

    # RTT calculations

    # Collect RTTs per router/destination
    rtt_data = {}  # ip -> list of rtt values (in ms)

    # Process TTL exceeded replies
    for reply in ttl_exceeded_replies:
        mk = reply['match_key']
        router_ip = reply['router_ip']

        if mk not in sent_packets:
            continue

        # find matching fragment 0 packet (same match key)
        # then apply RTT to all fragments with same IP id as packet
        for sent_pkt in sent_packets[mk]:
            rtt = (reply['time'] - sent_pkt['time']) * 1000.0 
            if rtt < 0:
                continue

            if router_ip not in rtt_data:
                rtt_data[router_ip] = []
            rtt_data[router_ip].append(rtt)

            # if probe was fragment 0 and ha matching
            # second fragment (same ip_id), apply same RTT to that
            if sent_pkt['frag_offset'] == 0 and sent_pkt['ip_id'] in traceroute_frags:
                # check if there are other fragments with this ip_id
                frag_info = traceroute_frags[sent_pkt['ip_id']]
                if len(frag_info['offsets']) > 1:
                    # find other fragments (offset != 0) and calculate their RTT too
                    for other_idx, (other_time, other_data) in enumerate(packets):
                        other_ip = parse_ip_header(other_data)
                        if other_ip is None:
                            continue
                        if (other_ip['src_ip'] == source_node and
                                other_ip['ip_id'] == sent_pkt['ip_id'] and
                                other_ip['frag_offset'] > 0):
                            other_rtt = (reply['time'] - other_time) * 1000.0
                            if other_rtt >= 0:
                                rtt_data[router_ip].append(other_rtt)

    # Process destination replies
    for reply in dest_replies:
        mk = reply['match_key']
        dest_ip = reply['dest_ip']

        if mk is None or mk not in sent_packets:
            continue

        for sent_pkt in sent_packets[mk]:
            rtt = (reply['time'] - sent_pkt['time']) * 1000.0
            if rtt < 0:
                continue

            if dest_ip not in rtt_data:
                rtt_data[dest_ip] = []
            rtt_data[dest_ip].append(rtt)

            # same fragmentation work as above
            if sent_pkt['frag_offset'] == 0 and sent_pkt['ip_id'] in traceroute_frags:
                frag_info = traceroute_frags[sent_pkt['ip_id']]
                if len(frag_info['offsets']) > 1:
                    for other_idx, (other_time, other_data) in enumerate(packets):
                        other_ip = parse_ip_header(other_data)
                        if other_ip is None:
                            continue
                        if (other_ip['src_ip'] == source_node and
                                other_ip['ip_id'] == sent_pkt['ip_id'] and
                                other_ip['frag_offset'] > 0):
                            other_rtt = (reply['time'] - other_time) * 1000.0
                            if other_rtt >= 0:
                                rtt_data[dest_ip].append(other_rtt)

    # helper to calc mean and std deviation
    def mean_and_sd(values):
        if not values:
            return 0.0, 0.0
        avg = sum(values) / len(values)
        if len(values) < 2:
            return avg, 0.0
        variance = sum((x - avg) ** 2 for x in values) / (len(values) - 1)
        sd = math.sqrt(variance)
        return avg, sd

    # print
    print("The IP address of the source node: " + str(source_node))
    print("The IP address of ultimate destination node: " + str(ultimate_dest_actual))

    print("The IP addresses of the intermediate destination nodes:")
    if intermediate_routers:
        for i, (ttl_val, rip) in enumerate(intermediate_routers):
            print("    router " + str(i + 1) + ": " + rip + ",")
    else:
        print("    None found")

    print("")
    print("The values in the protocol field of IP headers:")
    for p in sorted(relevant_protocols):
        print("    " + str(p) + ": " + proto_names.get(p, "Unknown"))

    print("")


    # We look for any datagram that was actually fragmented
    fragmented_datagrams = {}
    for ip_id, info in traceroute_frags.items():
        if len(info['offsets']) > 1:
            fragmented_datagrams[ip_id] = info

    if fragmented_datagrams:
        # grab just the first fragmented datagram to get the values
        first_frag_id = list(fragmented_datagrams.keys())[0]
        first_frag_info = fragmented_datagrams[first_frag_id]
        num_frags = len(first_frag_info['offsets'])
        max_off = first_frag_info['max_offset']
        print("The number of fragments created from the original datagram is: " + str(num_frags))
        print("")
        print("The offset of the last fragment is: " + str(max_off))
        print("")
    else:
        print("The number of fragments created from the original datagram is: 0")
        print("")
        print("The offset of the last fragment is: 0")
        print("")

    # RTT output
    for i, (ttl_val, router_ip) in enumerate(intermediate_routers):
        if router_ip in rtt_data and rtt_data[router_ip]:
            avg_rtt, sd_rtt = mean_and_sd(rtt_data[router_ip])
            print("The avg RTT between " + str(source_node) + " and " + router_ip +
                  " is: " + "{:.2f}".format(avg_rtt) + " ms, the s.d. is: " + "{:.2f}".format(sd_rtt) + " ms")
        else:
            print("The avg RTT between " + str(source_node) + " and " + router_ip +
                  " is: N/A ms, the s.d. is: N/A ms")

    # ultimate destination RTT
    if ultimate_dest_actual in rtt_data and rtt_data[ultimate_dest_actual]:
        avg_rtt, sd_rtt = mean_and_sd(rtt_data[ultimate_dest_actual])
        print("The avg RTT between " + str(source_node) + " and " + str(ultimate_dest_actual) +
              " is: " + "{:.2f}".format(avg_rtt) + " ms, the s.d. is: " + "{:.2f}".format(sd_rtt) + " ms")
    else:
        print("The avg RTT between " + str(source_node) + " and " + str(ultimate_dest_actual) +
              " is: N/A ms, the s.d. is: N/A ms")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        analyze_traceroute(sys.argv[1])
    else:
        print("Usage: python a3_analyzer.py <pcap_file>")

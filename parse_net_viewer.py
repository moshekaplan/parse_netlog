import base64, codecs, json, datetime
import ScapySessionBuilder
from scapy.all import *

fname = "edge-quic-test.json"
with open(fname) as fh:
    net_export_json = json.loads(fh.read())

# Extract out names for types of constants of interest
constants = net_export_json['constants']

capture_start = constants['timeTickOffset']
logevent_constants = constants['logEventTypes']

flattened_logEventTypes_constants = {}
for k, v in logevent_constants.items():
    flattened_logEventTypes_constants[v] = k


DECRYPTED_TRAFFIC_PORT = 44380

TCP_connections_seen = {}
SSL_connections_seen = {}
UDP_connections_seen = {}
# For UDP, we don't have a single connection with both the local and remote address, so we'll need a mapping of IDs to local address
# So we can build the connection objects.
UDP_connection_ids_to_remote_address = {}

packets = []
hex_output = b""
for event in net_export_json['events']:
    event_type_name = flattened_logEventTypes_constants[event['type']]
    event_id = event.get('source', {}).get('id')
    # print(event_type_name, event['type'])
    # There can be multiple TCP_CONNECT lines - we cheat by only storing the final one which includes both the local and remote addresses
    if event_type_name == "TCP_CONNECT" and "local_address" in event['params'] and "remote_address" in event['params']:
        src_ip, src_port = event['params']['local_address'].rsplit(":", 1)
        dest_ip, dest_port = event['params']['remote_address'].rsplit(":", 1)
        ipv4 = "." in src_ip
        sess = ScapySessionBuilder.TCPSessionBuilder(src_ip, dest_ip, int(src_port), int(dest_port), ipv4=ipv4)
        TCP_connections_seen[event_id] = sess
        # In case there is decrypted TLS traffic:
        sess = ScapySessionBuilder.TCPSessionBuilder(src_ip, dest_ip, int(src_port), DECRYPTED_TRAFFIC_PORT, ipv4=ipv4)
        SSL_connections_seen[event_id] = sess
    
    elif event_type_name == 'SOCKET_BYTES_RECEIVED':
        sess = TCP_connections_seen.get(event_id)
        if not sess:
            continue
        event_bytes = base64.b64decode(event['params']['bytes'])
        pkt = sess.add_client_payload(event_bytes)
        packets.append(pkt)
        
    elif event_type_name == 'SOCKET_BYTES_SENT':
        sess = TCP_connections_seen.get(event_id)
        if not sess:
            continue
        event_bytes = base64.b64decode(event['params']['bytes'])
        sess.add_server_payload(event_bytes)
        pkt = sess.add_client_payload(event_bytes)
        packets.append(pkt)

    elif event_type_name == 'SOCKET_CLOSED':
        sess = TCP_connections_seen.get(event_id)
        if not sess:
            continue
        pkts = sess.close_session()
        packets.extend(pkts)

    elif event_type_name == 'SSL_SOCKET_BYTES_RECEIVED':
        sess = SSL_connections_seen.get(event_id)
        if not sess:
            continue
        event_bytes = base64.b64decode(event['params']['bytes'])
        pkt = sess.add_client_payload(event_bytes)
        packets.append(pkt)

    elif event_type_name == 'SSL_SOCKET_BYTES_SENT':
        sess = SSL_connections_seen.get(event_id)
        if not sess:
            continue
        event_bytes = base64.b64decode(event['params']['bytes'])
        sess.add_server_payload(event_bytes)
        pkt = sess.add_client_payload(event_bytes)
        packets.append(pkt)

    elif event_type_name == 'UDP_BYTES_RECEIVED':
        sess = UDP_connections_seen.get(event_id)
        if not sess:
            continue
        event_bytes = base64.b64decode(event['params']['bytes'])
        pkt = sess.add_client_payload(event_bytes)
        packets.append(pkt)
        
    elif event_type_name == 'UDP_BYTES_SENT':
        sess = UDP_connections_seen.get(event_id)
        if not sess:
            continue
        event_bytes = base64.b64decode(event['params']['bytes'])
        sess.add_server_payload(event_bytes)
        pkt = sess.add_client_payload(event_bytes)
        packets.append(pkt)

    elif event_type_name == 'UDP_CONNECT' and 'params' in event and "address" in event['params']:
        UDP_connection_ids_to_remote_address[event_id] = event['params']['address']

    elif event_type_name == 'UDP_LOCAL_ADDRESS' and 'params' in event and "address" in event['params']:
        local_address = event['params']['address']
        remote_address = UDP_connection_ids_to_remote_address[event_id]
        
        src_ip, src_port = local_address.rsplit(":", 1)
        dest_ip, dest_port = remote_address.rsplit(":", 1)
        ipv4 = "." in src_ip
        sess = ScapySessionBuilder.UDPSessionBuilder(src_ip, dest_ip, int(src_port), int(dest_port), ipv4=ipv4)
        UDP_connections_seen[event_id] = sess

wrpcap(fname + '.pcap', packets)


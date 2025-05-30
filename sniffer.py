# sniffer.py
import traceback
from scapy.all import sniff, TCP, IP
from datetime import datetime

# Remove model and encoders loading here — they will be passed from app.py
# network_logs can stay if you want to keep local logs

network_logs = []  # shared list for storing logs (optional)

def start_sniffing(socketio, model, le_protocol, le_service, le_flag):
    def process_packet(packet):
        try:
            if not packet.haslayer(IP):
                return

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Example dummy features - customize to your real data extraction logic
            sample = [
                0,  # duration
                le_protocol.transform(['tcp'])[0],  # protocol_type
                le_service.transform(['http'])[0],  # service
                le_flag.transform(['SF'])[0],       # flag
                100,  # src_bytes
                200,  # dst_bytes
                1,    # logged_in
                0,    # wrong_fragment
                5,    # same_srv_count
                0.5   # same_srv_rate
            ]

            prediction = model.predict([sample])[0]
            result = "Attack Detected" if prediction != "normal" else "Normal"

            log_entry = {
                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'src': src_ip,
                'dst': dst_ip,
                'result': result
            }

            # Optionally keep local logs for history
            network_logs.append(log_entry)
            if len(network_logs) > 100:
                network_logs.pop(0)

            # Emit the new log entry to all connected SocketIO clients
            socketio.emit('new_log', log_entry, broadcast=True)

        except Exception as e:
            print("[!] Error processing packet:")
            traceback.print_exc()

    print("[*] Sniffing started... Press Ctrl+C to stop.")
    sniff(prn=process_packet, store=False)

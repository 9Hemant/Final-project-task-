#!/usr/bin/env python3
"""
Network Packet Sniffer with Anomaly Detection and Alert System
Author: Hemant Gaikwad
Description: Real-time network traffic analyzer with anomaly detection capabilities
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP
import sqlite3
import time
from datetime import datetime
from collections import defaultdict, Counter
import threading
import json
import argparse

class PacketSniffer:
    def __init__(self, interface='eth0', database='network_traffic.db'):
        self.interface = interface
        self.database = database
        self.packet_count = 0
        self.is_running = False
        
        # Anomaly detection tracking
        self.ip_port_tracker = defaultdict(set)
        self.syn_tracker = Counter()
        self.packet_rate_tracker = defaultdict(list)
        self.time_window = 60  # seconds
        
        # Thresholds
        self.PORT_SCAN_THRESHOLD = 50
        self.SYN_FLOOD_THRESHOLD = 100
        self.PACKET_FLOOD_THRESHOLD = 500
        self.LARGE_PACKET_SIZE = 1500
        
        self.init_database()
        
    def init_database(self):
        """Initialize SQLite database with required tables"""
        conn = sqlite3.connect(self.database)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                packet_size INTEGER,
                tcp_flags TEXT,
                payload_preview TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                alert_type TEXT,
                source_ip TEXT,
                description TEXT,
                severity TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        print(f"[+] Database initialized: {self.database}")
    
    def packet_callback(self, packet):
        """Process each captured packet"""
        if IP in packet:
            self.packet_count += 1
            
            packet_info = self.extract_packet_info(packet)
            self.log_packet(packet_info)
            anomalies = self.detect_anomalies(packet, packet_info)
            
            if anomalies:
                for anomaly in anomalies:
                    self.trigger_alert(anomaly)
            
            if self.packet_count % 100 == 0:
                print(f"[*] Packets captured: {self.packet_count}")
    
    def extract_packet_info(self, packet):
        """Extract relevant information from packet headers"""
        info = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'protocol': packet[IP].proto,
            'packet_size': len(packet),
            'src_port': None,
            'dst_port': None,
            'tcp_flags': None,
            'payload_preview': None
        }
        
        if TCP in packet:
            info['src_port'] = packet[TCP].sport
            info['dst_port'] = packet[TCP].dport
            info['protocol'] = 'TCP'
            info['tcp_flags'] = str(packet[TCP].flags)
        elif UDP in packet:
            info['src_port'] = packet[UDP].sport
            info['dst_port'] = packet[UDP].dport
            info['protocol'] = 'UDP'
        elif ICMP in packet:
            info['protocol'] = 'ICMP'
        
        if packet.haslayer('Raw'):
            payload = bytes(packet['Raw'].load)
            info['payload_preview'] = payload[:50].hex()
        
        return info
    
    def detect_anomalies(self, packet, packet_info):
        """Detect various types of network anomalies"""
        anomalies = []
        src_ip = packet_info['src_ip']
        dst_port = packet_info['dst_port']
        current_time = time.time()
        
        # Port Scanning Detection
        if dst_port:
            self.ip_port_tracker[src_ip].add(dst_port)
            if len(self.ip_port_tracker[src_ip]) > self.PORT_SCAN_THRESHOLD:
                anomalies.append({
                    'type': 'Port Scanning',
                    'source_ip': src_ip,
                    'description': f'Detected scanning {len(self.ip_port_tracker[src_ip])} ports',
                    'severity': 'HIGH'
                })
                self.ip_port_tracker[src_ip].clear()
        
        # SYN Flood Detection
        if TCP in packet and packet[TCP].flags == 'S':
            self.syn_tracker[src_ip] += 1
            if self.syn_tracker[src_ip] > self.SYN_FLOOD_THRESHOLD:
                anomalies.append({
                    'type': 'SYN Flood Attack',
                    'source_ip': src_ip,
                    'description': f'Detected {self.syn_tracker[src_ip]} SYN packets',
                    'severity': 'CRITICAL'
                })
                self.syn_tracker[src_ip] = 0
        
        # Packet Flooding Detection
        self.packet_rate_tracker[src_ip].append(current_time)
        self.packet_rate_tracker[src_ip] = [
            t for t in self.packet_rate_tracker[src_ip] 
            if current_time - t < self.time_window
        ]
        
        packet_rate = len(self.packet_rate_tracker[src_ip]) / self.time_window
        if packet_rate > (self.PACKET_FLOOD_THRESHOLD / 60):
            anomalies.append({
                'type': 'Packet Flooding',
                'source_ip': src_ip,
                'description': f'High packet rate: {packet_rate:.2f} packets/sec',
                'severity': 'HIGH'
            })
        
        # Large Packet Detection
        if packet_info['packet_size'] > self.LARGE_PACKET_SIZE:
            anomalies.append({
                'type': 'Oversized Packet',
                'source_ip': src_ip,
                'description': f'Packet size: {packet_info["packet_size"]} bytes',
                'severity': 'MEDIUM'
            })
        
        return anomalies
    
    def log_packet(self, packet_info):
        """Log packet information to database"""
        conn = sqlite3.connect(self.database)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO packets (timestamp, src_ip, dst_ip, src_port, dst_port, 
                                protocol, packet_size, tcp_flags, payload_preview)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            packet_info['timestamp'], packet_info['src_ip'], packet_info['dst_ip'],
            packet_info['src_port'], packet_info['dst_port'], packet_info['protocol'],
            packet_info['packet_size'], packet_info['tcp_flags'], 
            packet_info['payload_preview']
        ))
        
        conn.commit()
        conn.close()
    
    def trigger_alert(self, anomaly):
        """Trigger alert for detected anomaly"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        conn = sqlite3.connect(self.database)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO alerts (timestamp, alert_type, source_ip, description, severity)
            VALUES (?, ?, ?, ?, ?)
        ''', (timestamp, anomaly['type'], anomaly['source_ip'], 
              anomaly['description'], anomaly['severity']))
        
        conn.commit()
        conn.close()
        
        print(f"\\n[!] ALERT [{anomaly['severity']}]: {anomaly['type']}")
        print(f"    Source: {anomaly['source_ip']}")
        print(f"    Details: {anomaly['description']}")
        print(f"    Time: {timestamp}\\n")
        
        with open('alerts.log', 'a') as f:
            f.write(f"{timestamp} | {anomaly['severity']} | {anomaly['type']} | "
                   f"{anomaly['source_ip']} | {anomaly['description']}\\n")
    
    def start_sniffing(self, packet_count=0):
        """Start packet sniffing"""
        self.is_running = True
        print(f"[*] Starting packet capture on interface: {self.interface}")
        print(f"[*] Database: {self.database}")
        print(f"[*] Press Ctrl+C to stop...\\n")
        
        try:
            sniff(iface=self.interface, prn=self.packet_callback, 
                  store=0, count=packet_count)
        except KeyboardInterrupt:
            self.stop_sniffing()
    
    def stop_sniffing(self):
        """Stop packet sniffing and display summary"""
        self.is_running = False
        print(f"\\n[*] Packet capture stopped")
        print(f"[*] Total packets captured: {self.packet_count}")
        self.display_summary()
    
    def display_summary(self):
        """Display traffic summary from database"""
        conn = sqlite3.connect(self.database)
        cursor = conn.cursor()
        
        print("\\n" + "="*70)
        print("TRAFFIC SUMMARY")
        print("="*70)
        
        cursor.execute("SELECT protocol, COUNT(*) FROM packets GROUP BY protocol")
        protocols = cursor.fetchall()
        print("\\nProtocol Distribution:")
        for proto, count in protocols:
            print(f"  {proto}: {count} packets")
        
        cursor.execute('''
            SELECT src_ip, COUNT(*) as count FROM packets 
            GROUP BY src_ip ORDER BY count DESC LIMIT 5
        ''')
        top_sources = cursor.fetchall()
        print("\\nTop 5 Source IPs:")
        for ip, count in top_sources:
            print(f"  {ip}: {count} packets")
        
        cursor.execute("SELECT alert_type, COUNT(*) FROM alerts GROUP BY alert_type")
        alerts = cursor.fetchall()
        if alerts:
            print("\\nAlerts Detected:")
            for alert_type, count in alerts:
                print(f"  {alert_type}: {count} occurrences")
        else:
            print("\\nNo alerts detected")
        
        print("="*70)
        conn.close()

def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(
        description='Network Packet Sniffer with Anomaly Detection'
    )
    parser.add_argument('-i', '--interface', default='eth0',
                       help='Network interface to sniff (default: eth0)')
    parser.add_argument('-c', '--count', type=int, default=0,
                       help='Number of packets to capture (0 = infinite)')
    parser.add_argument('-d', '--database', default='network_traffic.db',
                       help='Database file path')
    
    args = parser.parse_args()
    
    print("="*70)
    print("Network Packet Sniffer with Anomaly Detection")
    print("="*70)
    
    sniffer = PacketSniffer(interface=args.interface, database=args.database)
    sniffer.start_sniffing(packet_count=args.count)

if __name__ == '__main__':
    main()

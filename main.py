import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
import threading
import tkinter as tk
from tkinter import ttk

# 数据包解析函数
def parse_packet(packet):
    result = {}
    # 解析ARP报文
    if packet.haslayer(ARP):
        result['Protocol'] = "ARP"
        result['Source'] = packet[ARP].psrc
        result['Destination'] = packet[ARP].pdst
    # 解析IP层报文
    elif packet.haslayer(IP):
        result['Protocol'] = "IP"
        result['Source'] = packet[IP].src
        result['Destination'] = packet[IP].dst
        result['Data'] = bytes(packet[IP].payload).decode('utf-8', errors='ignore')
        # 进一步解析ICMP/TCP/UDP层
        if packet.haslayer(ICMP):
            result['Protocol'] = "ICMP"
        elif packet.haslayer(TCP):
            result['Protocol'] = "TCP"
            result['Source Port'] = packet[TCP].sport
            result['Destination Port'] = packet[TCP].dport
        elif packet.haslayer(UDP):
            result['Protocol'] = "UDP"
            result['Source Port'] = packet[UDP].sport
            result['Destination Port'] = packet[UDP].dport
    return result

# 数据包捕获函数
def capture_packets(interface, stop_event, output_callback):
    def stop_filter(x):
        return stop_event.is_set()

    packets = scapy.sniff(iface=interface, prn=lambda x: output_callback(parse_packet(x)), stop_filter=stop_filter)

# GUI实现
def start_sniffer(interface):
    stop_event = threading.Event()

    def stop_sniffing():
        stop_event.set()

    threading.Thread(target=capture_packets, args=(interface, stop_event, display_packet)).start()

    return stop_event

# 数据包显示函数
def display_packet(parsed_data):
    if parsed_data:
        tree.insert("", "end", values=[parsed_data.get('Protocol'), parsed_data.get('Source'), parsed_data.get('Destination')])

# IP分片重组函数（简单示例）
def reassemble_ip_fragments(packets):
    fragments = {}
    for packet in packets:
        if packet.haslayer(IP) and packet[IP].flags == 1:  # MF标志位
            id = packet[IP].id
            if id not in fragments:
                fragments[id] = []
            fragments[id].append(packet)
    # 重组逻辑
    reassembled_packets = []
    for id, fragment_list in fragments.items():
        reassembled_packets.append(fragment_list[0])  # 简单逻辑示例
    return reassembled_packets

# 主程序
if __name__ == "__main__":
    root = tk.Tk()
    root.title("Network Sniffer")

    frame = ttk.Frame(root)
    frame.pack(fill="both", expand=True)

    tree = ttk.Treeview(frame, columns=("Protocol", "Source", "Destination"), show="headings")
    tree.heading("Protocol", text="Protocol")
    tree.heading("Source", text="Source")
    tree.heading("Destination", text="Destination")
    tree.pack(fill="both", expand=True)

    # 用户选择网卡
    interfaces = scapy.get_if_list()
    selected_interface = tk.StringVar()
    dropdown = ttk.Combobox(root, textvariable=selected_interface, values=interfaces)
    dropdown.pack()

    # 开始和停止按钮
    start_button = ttk.Button(root, text="Start", command=lambda: start_sniffer(selected_interface.get()))
    start_button.pack()

    stop_button = ttk.Button(root, text="Stop", command=lambda: stop_sniffing())
    stop_button.pack()

    root.mainloop()

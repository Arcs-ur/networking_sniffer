import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
import socket
import threading
import tkinter as tk
from tkinter import ttk

# 对packet进行解析，这里的packet是一个报文对象，返回一个字典result
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
        
        # 进行DNS查询，解析IP地址为域名
        result['Source'] = resolve_ip_to_hostname(result['Source'])
        result['Destination'] = resolve_ip_to_hostname(result['Destination'])
    
    return result

# IP到域名的解析函数
def resolve_ip_to_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]  # 返回域名
    except socket.herror:
        hostname = ip  # 如果解析失败，返回原始IP
    return hostname

# 数据包捕获函数，interface是网卡名，stop_event是停止捕获的事件，output_callback是数据包显示函数
def capture_packets(interface, stop_event, output_callback):
    def stop_filter(x):
        return stop_event.is_set()  # 当stop_event被设置时返回True，表示停止捕获
    
    # 捕获数据包，prn是回调函数，每捕获一个数据包，就调用一次output_callback函数
    scapy.sniff(iface=interface, prn=lambda x: output_callback(parse_packet(x)), stop_filter=stop_filter)

# GUI实现
global_stop_sniffing = None
def start_sniffer(interface):
    stop_event = threading.Event()

    def stop_sniffing():
        stop_event.set()  # 触发stop_event，表示停止抓包

    threading.Thread(target=capture_packets, args=(interface, stop_event, display_packet)).start()  # 启动数据包捕获线程
    global global_stop_sniffing
    global_stop_sniffing = stop_sniffing  # 将stop_sniffing存储为全局变量，方便在stop_button中使用
    return stop_event

def stop_sniffer_function():
    global global_stop_sniffing
    if global_stop_sniffing:
        global_stop_sniffing()  # 调用全局的stop_sniffing来停止抓包

# 数据包显示函数
def display_packet(parsed_data):
    if parsed_data:
        tree.insert("", "end", values=[parsed_data.get('Protocol'), parsed_data.get('Source'), parsed_data.get('Destination'), parsed_data.get('Data'), parsed_data.get('SrcPort'), parsed_data.get('DesPort')])

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

def get_network_interfaces():
    interfaces = scapy.get_if_list()  # 获取接口列表
    interface_names = []

    # 遍历所有接口
    for iface in interfaces:
        # 如果接口有一个有效的硬件地址（MAC地址），则它是一个实际的网络接口
        if scapy.get_if_hwaddr(iface) != "00:00:00:00:00:00":  # 确保排除没有硬件地址的接口
            interface_names.append(iface)
    
    return interface_names

# 主程序
if __name__ == "__main__":
    root = tk.Tk()
    root.title("Network Sniffer")

    frame = ttk.Frame(root)
    frame.pack(fill="both", expand=True)

    tree = ttk.Treeview(frame, columns=("Protocol", "Source", "Destination","Data","SrcPort","DesPort"), show="headings")
    tree.heading("Protocol", text="Protocol")
    tree.heading("Source", text="Source")
    tree.heading("Destination", text="Destination")
    tree.heading("Data", text="Data")
    tree.heading("SrcPort", text="Source Port")
    tree.heading("DesPort", text="Destination Port")
    tree.pack(fill="both", expand=True)

    # 用户选择网卡
    interfaces = get_network_interfaces()
    selected_interface = tk.StringVar()
    dropdown = ttk.Combobox(root, textvariable=selected_interface, values=interfaces)
    dropdown.pack()

    # 开始和停止按钮
    start_button = ttk.Button(root, text="Start", command=lambda: start_sniffer(selected_interface.get()))
    start_button.pack()

    stop_button = ttk.Button(root, text="Stop", command=lambda: stop_sniffer_function())
    stop_button.pack()

    root.mainloop()

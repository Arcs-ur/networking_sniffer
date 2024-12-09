import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.packet import Raw, Padding
import socket
import threading
import tkinter as tk
from tkinter import ttk
import json
import csv
from tkinter import filedialog
from tkinter import simpledialog

captured_data = []

def parse_packet(packet):
    result = {}
    if packet.haslayer(ARP):
        result['Protocol'] = "ARP"
        result['Source'] = packet[ARP].psrc
        result['Destination'] = packet[ARP].pdst
    elif packet.haslayer(IP):
        result['Protocol'] = "IP"
        result['Source'] = packet[IP].src
        result['Destination'] = packet[IP].dst
        result['Data'] = str(packet[IP].payload)
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
        if packet.haslayer(Raw):
            result['Raw Data'] = packet[Raw].load.hex()
            print(result['Raw Data'])
        if packet.haslayer(Padding):
            result['Padding Data'] = packet[Padding].load.hex()
            print(result['Padding Data'])
    #add_to_captured_data(result)
    # if packet.haslayer(Raw):
    #         result['Raw Data'] = packet[Raw].load
    # if packet.haslayer(Padding):
    #         result['Padding Data'] = packet[Padding].load
    return result

def resolve_ip_to_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = ip
    return hostname

def capture_packets(interface, stop_event, protocol_filter, source_ip_filter, destination_ip_filter, output_callback):
    def stop_filter(x):
        return stop_event.is_set()

    scapy.sniff(iface=interface, prn=lambda x: output_callback(parse_packet(x), protocol_filter, source_ip_filter, destination_ip_filter), stop_filter=stop_filter)

def start_sniffer(interface, protocol_filter, source_ip_filter, destination_ip_filter):
    stop_event = threading.Event()

    def stop_sniffing():
        stop_event.set()

    threading.Thread(target=capture_packets, args=(interface, stop_event, protocol_filter, source_ip_filter, destination_ip_filter, display_packet)).start()
    global global_stop_sniffing
    global_stop_sniffing = stop_sniffing
    return stop_event

def stop_sniffer_function():
    global global_stop_sniffing
    if global_stop_sniffing:
        global_stop_sniffing()

def display_packet(parsed_data, protocol_filter, source_ip_filter, destination_ip_filter):
    protocol_condition = protocol_filter.get().strip().lower()
    source_ip_condition = source_ip_filter.get().strip()
    destination_ip_condition = destination_ip_filter.get().strip()

    display = True

    if protocol_condition != "" and parsed_data.get("Protocol", "").lower() != protocol_condition:
        display = False

    if source_ip_condition != "" and parsed_data.get("Source", "") != source_ip_condition:
        display = False

    if destination_ip_condition != "" and parsed_data.get("Destination", "") != destination_ip_condition:
        display = False

    if display:
        tree.insert("", "end", values=[parsed_data.get('Protocol'), parsed_data.get('Source'), parsed_data.get('Destination'), parsed_data.get('Data'), parsed_data.get('Source Port'), parsed_data.get('Destination Port'), parsed_data.get('Raw Data'), parsed_data.get('Padding Data')])
        add_to_captured_data(parsed_data)
def reassemble_ip_fragments(packets):
    fragments = {}
    for packet in packets:
        if packet.haslayer(IP) and packet[IP].flags == 1:
            id = packet[IP].id
            if id not in fragments:
                fragments[id] = []
            fragments[id].append(packet)
    reassembled_packets = []
    for id, fragment_list in fragments.items():
        reassembled_packets.append(fragment_list[0])
    return reassembled_packets

def get_network_interfaces():
    interfaces = scapy.get_if_list()
    interface_names = []
    for iface in interfaces:
        if scapy.get_if_hwaddr(iface) != "00:00:00:00:00:00":
            interface_names.append(iface)
    return interface_names

def clear_packets():
    for item in tree.get_children():
        tree.delete(item)
    captured_data.clear()

def save_as_json(data):
    file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
    if file_path:
        with open(file_path, "w") as json_file:
            json.dump(data, json_file, indent=4)
    print(f"Saved as {file_path}")

def save_as_csv(data):
    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if file_path:
        with open(file_path, "w", newline='') as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
    print(f"Saved as {file_path}")

def export_packets():
    save_format = simpledialog.askstring("Save Format", "Enter the format to save as (json/csv):")
    #print(captured_data)
    if save_format == "json":
        save_as_json(captured_data)
    elif save_format == "csv":
        save_as_csv(captured_data)
    else:
        print("Invalid format. Please choose 'json' or 'csv'.")

def add_to_captured_data(parsed_data):
    if parsed_data:
        captured_data.append(parsed_data)

def on_item_select(event):
    selected_item = tree.selection()
    if selected_item:
        item = tree.item(selected_item)
        packet_info = item["values"]
        raw_data = packet_info[-2]
        padding_data = packet_info[-1]
        detail_text.delete(1.0, tk.END)
        detail_text.insert(tk.END, f"Raw Data:\n{raw_data}\n\nPadding Data:\n{padding_data}")

def create_filter_widgets(root):
    ttk.Label(root, text="Protocol Filter (e.g. TCP, UDP, ARP, *):").pack()
    protocol_filter = ttk.Entry(root)
    protocol_filter.pack()

    ttk.Label(root, text="Source IP Filter (e.g. 192.168.0.1, *):").pack()
    source_ip_filter = ttk.Entry(root)
    source_ip_filter.pack()

    ttk.Label(root, text="Destination IP Filter (e.g. 192.168.0.2, *):").pack()
    destination_ip_filter = ttk.Entry(root)
    destination_ip_filter.pack()

    return protocol_filter, source_ip_filter, destination_ip_filter

if __name__ == "__main__":
    root = tk.Tk()
    root.title("Network Sniffer")

    frame = ttk.Frame(root)
    frame.pack(fill="both", expand=True)

    tree = ttk.Treeview(frame, columns=("Protocol", "Source", "Destination", "Data", "Source Port", "Destination Port", "Raw Data", "Padding Data"), show="headings")
    tree.heading("Protocol", text="Protocol")
    tree.heading("Source", text="Source")
    tree.heading("Destination", text="Destination")
    tree.heading("Data", text="Data")
    tree.heading("Source Port", text="Source Port")
    tree.heading("Destination Port", text="Destination Port")
    tree.heading("Raw Data", text="Raw Data")
    tree.heading("Padding Data", text="Padding Data")
    tree.pack(fill="both", expand=True)
    
    detail_frame = ttk.Frame(root)
    detail_frame.pack(fill="both", expand=True)
    detail_text = tk.Text(detail_frame, wrap="word", height=10, width=50)
    detail_text.pack(fill="both", expand=True)
    tree.bind("<ButtonRelease-1>", on_item_select)

    interfaces = get_network_interfaces()
    selected_interface = tk.StringVar()
    dropdown = ttk.Combobox(root, textvariable=selected_interface, values=interfaces)
    dropdown.pack()

    protocol_filter, source_ip_filter, destination_ip_filter = create_filter_widgets(root)

    start_button = ttk.Button(root, text="Start", command=lambda: start_sniffer(selected_interface.get(), protocol_filter, source_ip_filter, destination_ip_filter))
    start_button.pack()

    stop_button = ttk.Button(root, text="Stop", command=stop_sniffer_function)
    stop_button.pack()

    clear_button = ttk.Button(root, text="Clear", command=clear_packets)
    clear_button.pack()

    export_button = ttk.Button(root, text="Export", command=export_packets)
    export_button.pack()

    root.mainloop()

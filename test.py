from scapy.all import *
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw, Padding
import socket
import threading
import tkinter as tk
from tkinter import ttk
import json
import csv
from tkinter import filedialog
from tkinter import simpledialog

# 创建一个 UDP 数据包
# from scapy.all import *

# # 创建一个包含大数据负载的 IP 数据包
# long_data = "A"*1000 # 创建一个包含1000个字符的负载
# packet = IP(dst="8.8.8.8")/ICMP()/Raw(load=long_data)

# # 发送数据包
# send(packet)
from scapy.all import *

# 创建一个包含长数据的负载
long_data = "A" * 100  # 创建一个包含1600个字符的负载

# 创建三次握手的 SYN 数据包
syn_packet = IP(dst="202.120.2.119")/TCP(dport=80, flags="S")
syn_ack_packet = sr1(syn_packet)

# 创建 ACK 数据包以完成三次握手
ack_packet = IP(dst="202.120.2.119")/TCP(dport=80, flags="A", ack=syn_ack_packet[TCP].seq + 1)
send(ack_packet)

# 发送数据负载
data_packet = IP(dst="202.120.2.119")/TCP(dport=80, flags="A", ack=syn_ack_packet[TCP].seq + 1)/Raw(load=long_data)
send(data_packet)
response = sr1(data_packet, timeout=30)  # 增加超时时间
if response:
    print(response.show())  # 显示响应包的详细信息
else:
    print("No response received.")
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

from scapy.all import *

# 创建一个超过MTU的数据包
# long_data = "A" * 1000  # 数据包大于常见的1500字节MTU

# # 发送带有大负载的包
# packet = IP(dst="8.8.8.8") / ICMP() / Raw(load=long_data)
# send(packet)
# print("Packet sent")
# 假设服务器为数据传输打开了端口 20
data_packet = IP(dst="8.8.8.8")/TCP(sport=RandShort(), dport=20, flags="A", seq=5000, ack=4002)/Raw(load="file1.txt\nfile2.txt\n")

# 发送数据包（模拟传输文件列表）
send(data_packet)
print("Packet sent")

from scapy.all import *
import os

# 定义目标服务器的 IP 和端口
server_ip = "8.8.8.8"
server_port = 12345

# 打开 JPEG 文件并读取为二进制数据
with open(r"C:\Users\陈楠\Desktop\Picture\黍.jpg", "rb") as f:
    file_data = f.read()

# 创建一个 TCP 连接，向目标服务器发送数据
syn_packet = IP(dst=server_ip)/TCP(sport=RandShort(), dport=server_port, flags="S", seq=1000)
syn_ack_response = sr1(syn_packet)

# 发送数据包（包括文件的二进制数据）
data_packet = IP(dst=server_ip)/TCP(sport=RandShort(), dport=server_port, flags="A", seq=1001, ack=2001)/Raw(load=file_data)
print(data_packet.show())
send(data_packet)

print("JPEG 文件已发送")

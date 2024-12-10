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
long_data = "A" * 1000  # 数据包大于常见的1500字节MTU

# 发送带有大负载的包
packet = IP(dst="8.8.8.8") / ICMP() / Raw(load=long_data)
send(packet)
print("Packet sent")
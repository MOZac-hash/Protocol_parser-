# coding=utf-8
import datetime
import threading
import time
import tkinter
from tkinter import *
from tkinter import font, filedialog, ttk
from tkinter.constants import *
from tkinter.filedialog import askopenfilename
from tkinter.messagebox import askyesno
from tkinter.scrolledtext import ScrolledText
from tkinter.ttk import Treeview
from tkinter import ttk

import ttkbootstrap as ttkb
from ttkbootstrap import Style

from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import *
from scapy.sendrecv import sniff
from scapy.utils import wrpcap

# Threads_Events
stop_sniff_event = threading.Event()
pause_sniff_event = threading.Event()
# ···total_catched
sniff_count = 0
# ···sniff_context
sniff_array = []


# Status_Bar
class StatusBar(Frame):

    def __init__(self, master):
        Frame.__init__(self, master)
        self.label = Label(self, bd=1, relief=SUNKEN, anchor=W)
        self.label.pack(fill=X)

    def set(self, fmt, *args):
        self.label.config(text=fmt % args)
        self.label.update_idletasks()


# change timestamp to real time
def timestamp2time(timestamp):
    time_array = time.localtime(timestamp)
    mytime = time.strftime("%Y-%m-%d %H:%M:%S", time_array)
    return mytime


def on_click_packet_list_tree(event):
    '''
    Click the event response function in the packet list. When clicking a packet in the packet list, the packet will be parsed in the protocol analysis area, and the hexadecimal content of the packet will be displayed in the hexdump area
    :param event: TreeView one-click event
    :return: None
    '''
    global sniff_array
    selected_item = event.widget.selection()
    packet_dissect_tree.delete(*packet_dissect_tree.get_children())
    packet_dissect_tree.column('Dissect', width=packet_list_frame.winfo_width())
    packet = sniff_array[int(selected_item[0]) - 1]

    lines = (packet.show(dump=True)).split('\n')
    last_tree_entry = None
    for line in lines:
        if line.startswith('#'):
            line = line.strip('#')
            last_tree_entry = packet_dissect_tree.insert('', 'end', text=line)
        else:
            packet_dissect_tree.insert(last_tree_entry, 'end', text=line)
        col_width = font.Font().measure(line)
        if packet_dissect_tree.column('Dissect', width=None) < col_width:
            packet_dissect_tree.column('Dissect', width=col_width)

    packetCheckSum = Ether(raw(packet))
    isIPChkSum = 'Error'
    isTCPChkSum = 'Error'
    isUDPChkSum = 'Error'
    if 'IP' in packet:
        # Caculate IP CheckSum
        if packetCheckSum[IP].chksum == packet[IP].chksum:
            isIPChkSum = 'OK'
        else:
            isIPChkSum = 'Error'
    if 'TCP' in packet:
        # Caculate TCP CheckSum
        if packetCheckSum[TCP].chksum == packet[TCP].chksum:
            isTCPChkSum = 'OK'
        else:
            isTCPChkSum = 'Error'
    elif 'UDP' in packet:
        # Caculate UDP CheckSum
        if packetCheckSum[UDP].chksum == packet[UDP].chksum:
            isUDPChkSum = 'OK'
        else:
            isUDPChkSum = 'Error'
    elif 'ICMP' in packet:
        # ICMP CheckSum
        if packetCheckSum[ICMP].chksum == packet[ICMP].chksum:
            isICMPChkSum = 'OK'
        else:
            isICMPChkSum = 'Error'
    if 'IP' in packet or 'IPv6' in packet:
        last_tree_entry = packet_dissect_tree.insert('', 'end', text=' CheckSum')
        packet_dissect_tree.insert(last_tree_entry, 'end', text='IP CheckSum' + '------' + isIPChkSum)
    if 'TCP' in packet:
        packet_dissect_tree.insert(last_tree_entry, 'end', text='TCP CheckSum' + '------' + isTCPChkSum)
    elif 'UDP' in packet:
        packet_dissect_tree.insert(last_tree_entry, 'end', text='UDP CheckSum' + '------' + isUDPChkSum)
    elif 'ICMP' in packet:
        packet_dissect_tree.insert(last_tree_entry, 'end', text='ICMP CheckSum' + '------' + isICMPChkSum)

    hexdump_scrolledtext['state'] = 'normal'
    hexdump_scrolledtext.delete(1.0, END)
    hexdump_scrolledtext.insert(END, hexdump(packet, dump=True))
    hexdump_scrolledtext['state'] = 'disabled'



# 生产函数
def packet_producer():
    sniff(prn=lambda pkt: packet_consumer(pkt), stop_filter=lambda pkt: stop_sniff_event.is_set(),
          filter=fitler_entry.get(), iface=interface_chosen)


# 消费者
def packet_consumer(pkt):
    global sniff_count
    global sniff_array
    if not pause_sniff_event.is_set():
        sniff_count = sniff_count + 1
        sniff_array.append(pkt)
        packet_time = timestamp2time(pkt.time)
        # 推导数据包的协议类型
        proto_names = ['TCP', 'UDP', 'ICMP', 'IPv6', 'IP', 'ARP', 'Ether', 'Unknown']
        proto = ''
        for pn in proto_names:
            if pn in pkt:
                proto = pn
                break
        if proto == 'ARP' or proto == 'Ether':
            src = pkt.src
            dst = pkt.dst
        else:
            if 'IPv6' in pkt:
                src = pkt[IPv6].src
                dst = pkt[IPv6].dst
            elif 'IP' in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
        length = len(pkt)
        info = pkt.summary()
        packet_list_tree.insert("", 'end', sniff_count, text=sniff_count,
                                values=(sniff_count, packet_time, src, dst, proto, length, info))
        packet_list_tree.update_idletasks()


# 将抓到的数据包保存为pcap格式的文件
def save_captured_data_to_file():
    fpath = filedialog.asksaveasfilename(defaultextension=".pcap",
                                         filetypes=[('pcap files', '.pcap'), ('cap files', '.cap'),
                                                    ('all files', '.*')])
    wrpcap(fpath, sniff_array)
    #   stop_sniff_event.clear()
    packet_dissect_tree.delete(*packet_dissect_tree.get_children())
    stop_button['state'] = 'disabled'
    pause_button['state'] = 'disabled'
    start_button['state'] = 'normal'
    save_button['state'] = 'disabled'
    quit_button['state'] = 'disabled'


# 读文件
def readPcap():
    filename = askopenfilename(filetypes=[('PCAP Files', '*.pcap')], title="打开pcap文件")
    if filename != '':
        global sniff_count
        global sniff_array
        # 如果是停止状态再打开，提示保存pcap文件
        if sniff_count != 0:
            save_captured_data_to_file()
            sniff_count = 0
            sniff_array = []
            packet_list_tree.delete(*packet_list_tree.get_children())
            packet_dissect_tree.delete(*packet_dissect_tree.get_children())
            stop_sniff_event.clear()
            pause_sniff_event.clear()
        sniff(prn=lambda pkt: packet_consumer(pkt), stop_filter=lambda pkt: stop_sniff_event.is_set(),
              filter=fitler_entry.get(), offline=filename)


#        sniff(prn=lambda x: packet_consumer(x), filter=fitler_entry['text'], offline=filename)


# 开始按钮单击响应函数，如果是停止后再次开始捕获，要提示用户保存已经捕获的数据
def start_capture():
    global sniff_count
    global sniff_array
    if stop_sniff_event.is_set():
        sniff_count = 0
        sniff_array.clear()
        packet_list_tree.delete(*packet_list_tree.get_children())
        stop_sniff_event.clear()
        pause_sniff_event.clear()
    else:
        sniff_count = 0
        sniff_array.clear()

    t = threading.Thread(target=packet_producer, name='LoopThread')
    t.start()
    stop_button['state'] = 'normal'
    pause_button['state'] = 'normal'
    start_button['state'] = 'disabled'
    save_button['state'] = 'disabled'
    quit_button['state'] = 'disabled'


# 暂停按钮单击响应函数
def pause_capture():
    if pause_button['text'] == '暂停':
        pause_sniff_event.set()
        pause_button['text'] = '继续'
    elif pause_button['text'] == '继续':
        pause_sniff_event.clear()
        pause_button['text'] = '暂停'


# 停止按钮单击响应函数
def stop_capture():
    stop_sniff_event.set()
    save_button['state'] = 'normal'
    pause_button['state'] = 'disabled'
    start_button['state'] = 'normal'


def go(*args):  # 处理事件，*args表示可变参数
    global interface_chosen
    interface_chosen = combox_list.get()


# 退出按钮单击响应函数,退出程序前要提示用户保存已经捕获的数据
def quit_program():
    if sniff_count != 0:
        save_captured_data_to_file()
    exit(0)

#获取网卡列表
interfaces_test = get_working_ifaces()
interfaces_temp = {}
for i in range(len(interfaces_test)):
    interfaces_temp[i] = interfaces_test[i].description
interfaces = [j for j in interfaces_temp.values()]
interface_chosen = interfaces[0]

# ---------------------以下代码负责绘制GUI界面---------------------
tk = tkinter.Tk()
style = Style(theme = "cosmo")
tk.title("协议分析器(作品赛测试组件) V0.0.1")
tk.iconbitmap('bitbug_favicon.ico')
# tk.resizable(0, 0)
# 带水平分割条的主窗体
main_panedwindow = PanedWindow(tk, sashrelief=RAISED, sashwidth=5, orient=VERTICAL)

# 顶部的按钮及过滤器区
toolbar = Frame(tk)
start_button = ttkb.Button(toolbar, width=8, text="开始", command=start_capture)
pause_button = ttkb.Button(toolbar, width=8, text="暂停", command=pause_capture)
stop_button = ttkb.Button(toolbar, width=8, text="停止", command=stop_capture)
open_button = ttkb.Button(toolbar, width=8, text="打开pcap", command=readPcap)
save_button = ttkb.Button(toolbar, width=8, text="保存数据", command=save_captured_data_to_file)
quit_button = ttkb.Button(toolbar, width=8, text="退出", command=quit_program)
start_button['state'] = 'normal'
pause_button['state'] = 'disabled'
stop_button['state'] = 'disabled'
open_button['state'] = 'normal'
save_button['state'] = 'disabled'
quit_button['state'] = 'normal'
filter_label = Label(toolbar, width=10, text="BPF过滤器：")
fitler_entry = Entry(toolbar)
comvalue = tkinter.StringVar()  # 窗体自带的文本，新建一个值
combox_label = Label(toolbar, width=10, text="  选择监听网卡：")
combox_list = ttk.Combobox(toolbar, textvariable=comvalue)
combox_list["values"] = interfaces
combox_list.current(0)#默认选择第一个
combox_list.bind("<<ComboboxSelected>>", go)  # 绑定事件,(下拉列表框被选中时，绑定go()函数)
start_button.pack(side=LEFT, padx=5)
pause_button.pack(side=LEFT, after=start_button, padx=10, pady=10)
stop_button.pack(side=LEFT, after=pause_button, padx=10, pady=10)
open_button.pack(side=LEFT, after=stop_button, padx=10, pady=10)
save_button.pack(side=LEFT, after=open_button, padx=10, pady=10)
quit_button.pack(side=LEFT, after=save_button, padx=10, pady=10)
combox_label.pack(side=LEFT, fill=X, after=quit_button,padx=20)
combox_list.pack(side=LEFT, fill=X, after=combox_label)
filter_label.pack(side=LEFT, after=combox_list, padx=10, pady=10)
fitler_entry.pack(side=LEFT, after=filter_label, padx=10, pady=10, fill=X, expand=YES)
toolbar.pack(side=TOP, fill=X)

# 数据包列表区
packet_list_frame = Frame()
packet_list_sub_frame = Frame(packet_list_frame)
packet_list_tree = Treeview(packet_list_sub_frame, selectmode='browse')
packet_list_tree.bind('<<TreeviewSelect>>', on_click_packet_list_tree)
# 数据包列表垂直滚动条
packet_list_vscrollbar = Scrollbar(packet_list_sub_frame, orient="vertical", command=packet_list_tree.yview)
packet_list_vscrollbar.pack(side=RIGHT, fill=Y, expand=YES)
packet_list_tree.configure(yscrollcommand=packet_list_vscrollbar.set)
packet_list_sub_frame.pack(side=TOP, fill=BOTH, expand=YES)
# 数据包列表水平滚动条
packet_list_hscrollbar = Scrollbar(packet_list_frame, orient="horizontal", command=packet_list_tree.xview)
packet_list_hscrollbar.pack(side=BOTTOM, fill=X, expand=YES)
packet_list_tree.configure(xscrollcommand=packet_list_hscrollbar.set)
# 数据包列表区列标题
packet_list_tree["columns"] = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
packet_list_column_width = [100, 180, 160, 160, 100, 100, 800]
packet_list_tree['show'] = 'headings'
for column_name, column_width in zip(packet_list_tree["columns"], packet_list_column_width):
    packet_list_tree.column(column_name, width=column_width, anchor='w')
    packet_list_tree.heading(column_name, text=column_name)
packet_list_tree.pack(side=LEFT, fill=X, expand=YES)
packet_list_frame.pack(side=TOP, fill=X, padx=5, pady=5, expand=YES, anchor='n')
# 将数据包列表区加入到主窗体
main_panedwindow.add(packet_list_frame)

# 协议解析区
packet_dissect_frame = Frame()
packet_dissect_sub_frame = Frame(packet_dissect_frame)
packet_dissect_tree = Treeview(packet_dissect_sub_frame, selectmode='browse')
packet_dissect_tree["columns"] = ("Dissect",)
packet_dissect_tree.column('Dissect', anchor='w')
packet_dissect_tree.heading('#0', text='Packet Dissection', anchor='w')
packet_dissect_tree.pack(side=LEFT, fill=BOTH, expand=YES)
# 协议解析区垂直滚动条
packet_dissect_vscrollbar = Scrollbar(packet_dissect_sub_frame, orient="vertical", command=packet_dissect_tree.yview)
packet_dissect_vscrollbar.pack(side=RIGHT, fill=Y)
packet_dissect_tree.configure(yscrollcommand=packet_dissect_vscrollbar.set)
packet_dissect_sub_frame.pack(side=TOP, fill=X, expand=YES)
# 协议解析区水平滚动条
packet_dissect_hscrollbar = Scrollbar(packet_dissect_frame, orient="horizontal", command=packet_dissect_tree.xview)
packet_dissect_hscrollbar.pack(side=BOTTOM, fill=X)
packet_dissect_tree.configure(xscrollcommand=packet_dissect_hscrollbar.set)
packet_dissect_frame.pack(side=LEFT, fill=X, padx=5, pady=5, expand=YES)
# 将协议解析区加入到主窗体
main_panedwindow.add(packet_dissect_frame)

# hexdump区
hexdump_scrolledtext = ScrolledText(height=10)
hexdump_scrolledtext['state'] = 'disabled'
# 将hexdump区区加入到主窗体
main_panedwindow.add(hexdump_scrolledtext)

main_panedwindow.pack(fill=BOTH, expand=1)

# 状态栏
status_bar = StatusBar(tk)
status_bar.pack(side=BOTTOM, fill=X)
tk.mainloop()

import datetime #line:2
import threading #line:3
import time #line:4
import tkinter #line:5
from tkinter import *#line:6
from tkinter import font ,filedialog ,ttk #line:7
from tkinter .constants import *#line:8
from tkinter .filedialog import askopenfilename #line:9
from tkinter .messagebox import askyesno #line:10
from tkinter .scrolledtext import ScrolledText #line:11
from tkinter .ttk import Treeview #line:12
from tkinter import ttk #line:13
import ttkbootstrap as ttkb #line:15
from ttkbootstrap import Style #line:16
from scapy .all import *#line:18
from scapy .layers .inet import *#line:19
from scapy .layers .inet6 import IPv6 #line:20
from scapy .layers .l2 import *#line:21
from scapy .sendrecv import sniff #line:22
from scapy .utils import wrpcap #line:23
stop_sniff_event =threading .Event ()#line:26
pause_sniff_event =threading .Event ()#line:27
sniff_count =0 #line:29
sniff_array =[]#line:31
class StatusBar (Frame ):#line:35
    def __init__ (OOO00OOOOOOO0O00O ,OO000O000O0O0O0OO ):#line:37
        Frame .__init__ (OOO00OOOOOOO0O00O ,OO000O000O0O0O0OO )#line:38
        OOO00OOOOOOO0O00O .label =Label (OOO00OOOOOOO0O00O ,bd =1 ,relief =SUNKEN ,anchor =W )#line:39
        OOO00OOOOOOO0O00O .label .pack (fill =X )#line:40
    def set (O0O0OOO00O0OO0O00 ,O00O000OOOOO00OO0 ,*O000000OOO0O0O0O0 ):#line:42
        O0O0OOO00O0OO0O00 .label .config (text =O00O000OOOOO00OO0 %O000000OOO0O0O0O0 )#line:43
        O0O0OOO00O0OO0O00 .label .update_idletasks ()#line:44
def timestamp2time (O00OOO000O0OO0OO0 ):#line:48
    OOOOO000000O00O00 =time .localtime (O00OOO000O0OO0OO0 )#line:49
    OO00OO00O000OOOOO =time .strftime ("%Y-%m-%d %H:%M:%S",OOOOO000000O00O00 )#line:50
    return OO00OO00O000OOOOO #line:51
def on_click_packet_list_tree (OOOO00O0OOO0O0O00 ):#line:54
    ""#line:59
    global sniff_array #line:60
    O00O00OOO0O0OO00O =OOOO00O0OOO0O0O00 .widget .selection ()#line:61
    packet_dissect_tree .delete (*packet_dissect_tree .get_children ())#line:62
    packet_dissect_tree .column ('Dissect',width =packet_list_frame .winfo_width ())#line:63
    OOOOOOOO0O0O0O0OO =sniff_array [int (O00O00OOO0O0OO00O [0 ])-1 ]#line:64
    O00O0OOOOOOOOOOO0 =(OOOOOOOO0O0O0O0OO .show (dump =True )).split ('\n')#line:66
    OO0OOOOOOOO0O0OOO =None #line:67
    for OO0O000O0000O0O0O in O00O0OOOOOOOOOOO0 :#line:68
        if OO0O000O0000O0O0O .startswith ('#'):#line:69
            OO0O000O0000O0O0O =OO0O000O0000O0O0O .strip ('#')#line:70
            OO0OOOOOOOO0O0OOO =packet_dissect_tree .insert ('','end',text =OO0O000O0000O0O0O )#line:71
        else :#line:72
            packet_dissect_tree .insert (OO0OOOOOOOO0O0OOO ,'end',text =OO0O000O0000O0O0O )#line:73
        OOO0OO00OO0O000O0 =font .Font ().measure (OO0O000O0000O0O0O )#line:74
        if packet_dissect_tree .column ('Dissect',width =None )<OOO0OO00OO0O000O0 :#line:75
            packet_dissect_tree .column ('Dissect',width =OOO0OO00OO0O000O0 )#line:76
    OO00000000O00O0O0 =Ether (raw (OOOOOOOO0O0O0O0OO ))#line:78
    O0OO0OO00000000O0 ='Error'#line:79
    OOOOO000O000OO00O ='Error'#line:80
    OO0OO0O000OO00OOO ='Error'#line:81
    if 'IP'in OOOOOOOO0O0O0O0OO :#line:82
        if OO00000000O00O0O0 [IP ].chksum ==OOOOOOOO0O0O0O0OO [IP ].chksum :#line:84
            O0OO0OO00000000O0 ='OK'#line:85
        else :#line:86
            O0OO0OO00000000O0 ='Error'#line:87
    if 'TCP'in OOOOOOOO0O0O0O0OO :#line:88
        if OO00000000O00O0O0 [TCP ].chksum ==OOOOOOOO0O0O0O0OO [TCP ].chksum :#line:90
            OOOOO000O000OO00O ='OK'#line:91
        else :#line:92
            OOOOO000O000OO00O ='Error'#line:93
    elif 'UDP'in OOOOOOOO0O0O0O0OO :#line:94
        if OO00000000O00O0O0 [UDP ].chksum ==OOOOOOOO0O0O0O0OO [UDP ].chksum :#line:96
            OO0OO0O000OO00OOO ='OK'#line:97
        else :#line:98
            OO0OO0O000OO00OOO ='Error'#line:99
    elif 'ICMP'in OOOOOOOO0O0O0O0OO :#line:100
        if OO00000000O00O0O0 [ICMP ].chksum ==OOOOOOOO0O0O0O0OO [ICMP ].chksum :#line:102
            O000000OOO000O00O ='OK'#line:103
        else :#line:104
            O000000OOO000O00O ='Error'#line:105
    if 'IP'in OOOOOOOO0O0O0O0OO or 'IPv6'in OOOOOOOO0O0O0O0OO :#line:106
        OO0OOOOOOOO0O0OOO =packet_dissect_tree .insert ('','end',text =' CheckSum')#line:107
        packet_dissect_tree .insert (OO0OOOOOOOO0O0OOO ,'end',text ='IP CheckSum'+'------'+O0OO0OO00000000O0 )#line:108
    if 'TCP'in OOOOOOOO0O0O0O0OO :#line:109
        packet_dissect_tree .insert (OO0OOOOOOOO0O0OOO ,'end',text ='TCP CheckSum'+'------'+OOOOO000O000OO00O )#line:110
    elif 'UDP'in OOOOOOOO0O0O0O0OO :#line:111
        packet_dissect_tree .insert (OO0OOOOOOOO0O0OOO ,'end',text ='UDP CheckSum'+'------'+OO0OO0O000OO00OOO )#line:112
    elif 'ICMP'in OOOOOOOO0O0O0O0OO :#line:113
        packet_dissect_tree .insert (OO0OOOOOOOO0O0OOO ,'end',text ='ICMP CheckSum'+'------'+O000000OOO000O00O )#line:114
    hexdump_scrolledtext ['state']='normal'#line:116
    hexdump_scrolledtext .delete (1.0 ,END )#line:117
    hexdump_scrolledtext .insert (END ,hexdump (OOOOOOOO0O0O0O0OO ,dump =True ))#line:118
    hexdump_scrolledtext ['state']='disabled'#line:119
def packet_producer ():#line:124
    sniff (prn =lambda OOOO0O00O0O0O00OO :packet_consumer (OOOO0O00O0O0O00OO ),stop_filter =lambda O0O0OOO0O00OOO00O :stop_sniff_event .is_set (),filter =fitler_entry .get (),iface =interface_chosen )#line:126
def packet_consumer (O00O000OO0OO00OO0 ):#line:130
    global sniff_count #line:131
    global sniff_array #line:132
    if not pause_sniff_event .is_set ():#line:133
        sniff_count =sniff_count +1 #line:134
        sniff_array .append (O00O000OO0OO00OO0 )#line:135
        O0O00OO00O0OOO000 =timestamp2time (O00O000OO0OO00OO0 .time )#line:136
        OO0000OO0OOOOO00O =['TCP','UDP','ICMP','IPv6','IP','ARP','Ether','Unknown']#line:138
        O0OOO000O0O0O0OOO =''#line:139
        for O000O0O000O0O0O00 in OO0000OO0OOOOO00O :#line:140
            if O000O0O000O0O0O00 in O00O000OO0OO00OO0 :#line:141
                O0OOO000O0O0O0OOO =O000O0O000O0O0O00 #line:142
                break #line:143
        if O0OOO000O0O0O0OOO =='ARP'or O0OOO000O0O0O0OOO =='Ether':#line:144
            OOO0OO0OO0O0OOO00 =O00O000OO0OO00OO0 .src #line:145
            O0OOOOOO0OO0O000O =O00O000OO0OO00OO0 .dst #line:146
        else :#line:147
            if 'IPv6'in O00O000OO0OO00OO0 :#line:148
                OOO0OO0OO0O0OOO00 =O00O000OO0OO00OO0 [IPv6 ].src #line:149
                O0OOOOOO0OO0O000O =O00O000OO0OO00OO0 [IPv6 ].dst #line:150
            elif 'IP'in O00O000OO0OO00OO0 :#line:151
                OOO0OO0OO0O0OOO00 =O00O000OO0OO00OO0 [IP ].src #line:152
                O0OOOOOO0OO0O000O =O00O000OO0OO00OO0 [IP ].dst #line:153
        OOOO00O00OO00OO00 =len (O00O000OO0OO00OO0 )#line:154
        O000O0OOO0OO0O00O =O00O000OO0OO00OO0 .summary ()#line:155
        packet_list_tree .insert ("",'end',sniff_count ,text =sniff_count ,values =(sniff_count ,O0O00OO00O0OOO000 ,OOO0OO0OO0O0OOO00 ,O0OOOOOO0OO0O000O ,O0OOO000O0O0O0OOO ,OOOO00O00OO00OO00 ,O000O0OOO0OO0O00O ))#line:157
        packet_list_tree .update_idletasks ()#line:158
def save_captured_data_to_file ():#line:162
    O0OO00000O00OO000 =filedialog .asksaveasfilename (defaultextension =".pcap",filetypes =[('pcap files','.pcap'),('cap files','.cap'),('all files','.*')])#line:165
    wrpcap (O0OO00000O00OO000 ,sniff_array )#line:166
    packet_dissect_tree .delete (*packet_dissect_tree .get_children ())#line:168
    stop_button ['state']='disabled'#line:169
    pause_button ['state']='disabled'#line:170
    start_button ['state']='normal'#line:171
    save_button ['state']='disabled'#line:172
    quit_button ['state']='disabled'#line:173
def readPcap ():#line:177
    O000O0O0OO0OO0OO0 =askopenfilename (filetypes =[('PCAP Files','*.pcap')],title ="打开pcap文件")#line:178
    if O000O0O0OO0OO0OO0 !='':#line:179
        global sniff_count #line:180
        global sniff_array #line:181
        if sniff_count !=0 :#line:183
            save_captured_data_to_file ()#line:184
            sniff_count =0 #line:185
            sniff_array =[]#line:186
            packet_list_tree .delete (*packet_list_tree .get_children ())#line:187
            packet_dissect_tree .delete (*packet_dissect_tree .get_children ())#line:188
            stop_sniff_event .clear ()#line:189
            pause_sniff_event .clear ()#line:190
        sniff (prn =lambda O00OO00O000O0OO0O :packet_consumer (O00OO00O000O0OO0O ),stop_filter =lambda O0OOO00O00OO0O00O :stop_sniff_event .is_set (),filter =fitler_entry .get (),offline =O000O0O0OO0OO0OO0 )#line:192
def start_capture ():#line:199
    global sniff_count #line:200
    global sniff_array #line:201
    if stop_sniff_event .is_set ():#line:202
        sniff_count =0 #line:203
        sniff_array .clear ()#line:204
        packet_list_tree .delete (*packet_list_tree .get_children ())#line:205
        stop_sniff_event .clear ()#line:206
        pause_sniff_event .clear ()#line:207
    else :#line:208
        sniff_count =0 #line:209
        sniff_array .clear ()#line:210
    OOOO0000000O00O0O =threading .Thread (target =packet_producer ,name ='LoopThread')#line:212
    OOOO0000000O00O0O .start ()#line:213
    stop_button ['state']='normal'#line:214
    pause_button ['state']='normal'#line:215
    start_button ['state']='disabled'#line:216
    save_button ['state']='disabled'#line:217
    quit_button ['state']='disabled'#line:218
def pause_capture ():#line:222
    if pause_button ['text']=='暂停':#line:223
        pause_sniff_event .set ()#line:224
        pause_button ['text']='继续'#line:225
    elif pause_button ['text']=='继续':#line:226
        pause_sniff_event .clear ()#line:227
        pause_button ['text']='暂停'#line:228
def stop_capture ():#line:232
    stop_sniff_event .set ()#line:233
    save_button ['state']='normal'#line:234
    pause_button ['state']='disabled'#line:235
    start_button ['state']='normal'#line:236
def go (*O000O0OOOOOO0OOOO ):#line:239
    global interface_chosen #line:240
    interface_chosen =combox_list .get ()#line:241
def quit_program ():#line:245
    if sniff_count !=0 :#line:246
        save_captured_data_to_file ()#line:247
    exit (0 )#line:248
interfaces_test =get_working_ifaces ()#line:251
interfaces_temp ={}#line:252
for i in range (len (interfaces_test )):#line:253
    interfaces_temp [i ]=interfaces_test [i ].description #line:254
interfaces =[OOOOO0OO0O0000OOO for OOOOO0OO0O0000OOO in interfaces_temp .values ()]#line:255
interface_chosen =interfaces [0 ]#line:256
tk =tkinter .Tk ()#line:259
style =Style (theme ="cosmo")#line:260
tk .title ("协议分析器(作品赛测试组件) V0.0.1")#line:261
tk .iconbitmap ('bitbug_favicon.ico')#line:262
main_panedwindow =PanedWindow (tk ,sashrelief =RAISED ,sashwidth =5 ,orient =VERTICAL )#line:265
toolbar =Frame (tk )#line:268
start_button =ttkb .Button (toolbar ,width =8 ,text ="开始",command =start_capture )#line:269
pause_button =ttkb .Button (toolbar ,width =8 ,text ="暂停",command =pause_capture )#line:270
stop_button =ttkb .Button (toolbar ,width =8 ,text ="停止",command =stop_capture )#line:271
open_button =ttkb .Button (toolbar ,width =8 ,text ="打开pcap",command =readPcap )#line:272
save_button =ttkb .Button (toolbar ,width =8 ,text ="保存数据",command =save_captured_data_to_file )#line:273
quit_button =ttkb .Button (toolbar ,width =8 ,text ="退出",command =quit_program )#line:274
start_button ['state']='normal'#line:275
pause_button ['state']='disabled'#line:276
stop_button ['state']='disabled'#line:277
open_button ['state']='normal'#line:278
save_button ['state']='disabled'#line:279
quit_button ['state']='normal'#line:280
filter_label =Label (toolbar ,width =10 ,text ="BPF过滤器：")#line:281
fitler_entry =Entry (toolbar )#line:282
comvalue =tkinter .StringVar ()#line:283
combox_label =Label (toolbar ,width =10 ,text ="  选择监听网卡：")#line:284
combox_list =ttk .Combobox (toolbar ,textvariable =comvalue )#line:285
combox_list ["values"]=interfaces #line:286
combox_list .current (0 )#line:287
combox_list .bind ("<<ComboboxSelected>>",go )#line:288
start_button .pack (side =LEFT ,padx =5 )#line:289
pause_button .pack (side =LEFT ,after =start_button ,padx =10 ,pady =10 )#line:290
stop_button .pack (side =LEFT ,after =pause_button ,padx =10 ,pady =10 )#line:291
open_button .pack (side =LEFT ,after =stop_button ,padx =10 ,pady =10 )#line:292
save_button .pack (side =LEFT ,after =open_button ,padx =10 ,pady =10 )#line:293
quit_button .pack (side =LEFT ,after =save_button ,padx =10 ,pady =10 )#line:294
combox_label .pack (side =LEFT ,fill =X ,after =quit_button ,padx =20 )#line:295
combox_list .pack (side =LEFT ,fill =X ,after =combox_label )#line:296
filter_label .pack (side =LEFT ,after =combox_list ,padx =10 ,pady =10 )#line:297
fitler_entry .pack (side =LEFT ,after =filter_label ,padx =10 ,pady =10 ,fill =X ,expand =YES )#line:298
toolbar .pack (side =TOP ,fill =X )#line:299
packet_list_frame =Frame ()#line:302
packet_list_sub_frame =Frame (packet_list_frame )#line:303
packet_list_tree =Treeview (packet_list_sub_frame ,selectmode ='browse')#line:304
packet_list_tree .bind ('<<TreeviewSelect>>',on_click_packet_list_tree )#line:305
packet_list_vscrollbar =Scrollbar (packet_list_sub_frame ,orient ="vertical",command =packet_list_tree .yview )#line:307
packet_list_vscrollbar .pack (side =RIGHT ,fill =Y ,expand =YES )#line:308
packet_list_tree .configure (yscrollcommand =packet_list_vscrollbar .set )#line:309
packet_list_sub_frame .pack (side =TOP ,fill =BOTH ,expand =YES )#line:310
packet_list_hscrollbar =Scrollbar (packet_list_frame ,orient ="horizontal",command =packet_list_tree .xview )#line:312
packet_list_hscrollbar .pack (side =BOTTOM ,fill =X ,expand =YES )#line:313
packet_list_tree .configure (xscrollcommand =packet_list_hscrollbar .set )#line:314
packet_list_tree ["columns"]=("No.","Time","Source","Destination","Protocol","Length","Info")#line:316
packet_list_column_width =[100 ,180 ,160 ,160 ,100 ,100 ,800 ]#line:317
packet_list_tree ['show']='headings'#line:318
for column_name ,column_width in zip (packet_list_tree ["columns"],packet_list_column_width ):#line:319
    packet_list_tree .column (column_name ,width =column_width ,anchor ='w')#line:320
    packet_list_tree .heading (column_name ,text =column_name )#line:321
packet_list_tree .pack (side =LEFT ,fill =X ,expand =YES )#line:322
packet_list_frame .pack (side =TOP ,fill =X ,padx =5 ,pady =5 ,expand =YES ,anchor ='n')#line:323
main_panedwindow .add (packet_list_frame )#line:325
packet_dissect_frame =Frame ()#line:328
packet_dissect_sub_frame =Frame (packet_dissect_frame )#line:329
packet_dissect_tree =Treeview (packet_dissect_sub_frame ,selectmode ='browse')#line:330
packet_dissect_tree ["columns"]=("Dissect",)#line:331
packet_dissect_tree .column ('Dissect',anchor ='w')#line:332
packet_dissect_tree .heading ('#0',text ='Packet Dissection',anchor ='w')#line:333
packet_dissect_tree .pack (side =LEFT ,fill =BOTH ,expand =YES )#line:334
packet_dissect_vscrollbar =Scrollbar (packet_dissect_sub_frame ,orient ="vertical",command =packet_dissect_tree .yview )#line:336
packet_dissect_vscrollbar .pack (side =RIGHT ,fill =Y )#line:337
packet_dissect_tree .configure (yscrollcommand =packet_dissect_vscrollbar .set )#line:338
packet_dissect_sub_frame .pack (side =TOP ,fill =X ,expand =YES )#line:339
packet_dissect_hscrollbar =Scrollbar (packet_dissect_frame ,orient ="horizontal",command =packet_dissect_tree .xview )#line:341
packet_dissect_hscrollbar .pack (side =BOTTOM ,fill =X )#line:342
packet_dissect_tree .configure (xscrollcommand =packet_dissect_hscrollbar .set )#line:343
packet_dissect_frame .pack (side =LEFT ,fill =X ,padx =5 ,pady =5 ,expand =YES )#line:344
main_panedwindow .add (packet_dissect_frame )#line:346
hexdump_scrolledtext =ScrolledText (height =10 )#line:349
hexdump_scrolledtext ['state']='disabled'#line:350
main_panedwindow .add (hexdump_scrolledtext )#line:352
main_panedwindow .pack (fill =BOTH ,expand =1 )#line:354
status_bar =StatusBar (tk )#line:357
status_bar .pack (side =BOTTOM ,fill =X )#line:358
tk .mainloop ()#line:359

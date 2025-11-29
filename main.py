import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, sendp, Ether, ARP, IP, TCP, UDP, ICMP, Raw
import threading
import time
import hashlib

PORT1 = "Intel(R) Wireless-AC 9560 160MHz"
PORT2 = "Intel(R) Wireless-AaC 9560 160MHz"

#PORT1 = "Realtek PCIe GbE Family Controller"
#PORT2 = "Realtek USB GbE Family Controller"
#Intel(R) Wireless-AC 9560 160MHz

class Switch:
    def __init__(self):
        self.mac_table = {}
        self.record_timeout = 60
        self.stats = {
            'Ethernet II': {'in': [0, 0], 'out': [0, 0]},
            'ARP':         {'in': [0, 0], 'out': [0, 0]},
            'IP':          {'in': [0, 0], 'out': [0, 0]},
            'TCP':         {'in': [0, 0], 'out': [0, 0]},
            'UDP':         {'in': [0, 0], 'out': [0, 0]},
            'ICMP':        {'in': [0, 0], 'out': [0, 0]},
            'HTTP':        {'in': [0, 0], 'out': [0, 0]}
        }
        self.port_stats = {1: {'in': 0, 'out': 0}, 2: {'in': 0, 'out': 0}}
        self.recent_packets = {}
        self.recent_packets_lock = threading.Lock()
        self.port_last_activity = {1: time.time(), 2: time.time()}
        self.port_status = {1: "Disconnected", 2: "Disconnected"}
        self.acl_rules = []  

    def recent_check(self, packet):
        hash_value = hashlib.md5(bytes(packet)).hexdigest()
        
        with self.recent_packets_lock:
            packet_seen = self.recent_packets.get(hash_value)
            if packet_seen is None:
                self.recent_packets[hash_value] = time.monotonic()
                return False
            return True

    def clean_old(self):
        while True:
            threshold = time.monotonic() - 2
            with self.recent_packets_lock:
                outdated = [key for key, timestamp in self.recent_packets.items() if timestamp < threshold]
                for key in outdated:
                    self.recent_packets.pop(key, None)
            time.sleep(1)

    def update_mac_table(self, mac, port):
        self.mac_table[mac] = (port, time.time())

    def expire_mac_records(self):
        while True:
            current_time = time.time()
            self.mac_table = {mac: (port, t) for mac, (port, t) in self.mac_table.items()
                              if current_time - t <= self.record_timeout}
            time.sleep(1)

    def update_stats(self, packet, direction, port):
        if Ether in packet:
            self.stats['Ethernet II'][direction][port-1] += 1

            if ARP in packet:
                self.stats['ARP'][direction][port-1] += 1

            elif IP in packet:
                self.stats['IP'][direction][port-1] += 1

                if TCP in packet:
                    self.stats['TCP'][direction][port-1] += 1

                    if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                        self.stats['HTTP'][direction][port-1] += 1

                elif UDP in packet:
                    self.stats['UDP'][direction][port-1] += 1

                elif ICMP in packet:
                    self.stats['ICMP'][direction][port-1] += 1

        self.port_stats[port][direction] += 1

        if direction == 'in':
            self.port_last_activity[port] = time.time()
            self.port_status[port] = "Connected"


    def is_port_connected(self, port):
        return self.port_status[port] == "Connected"

    def forward_packet(self, packet, input_port):
        def try_send(out_port):
            if self.is_port_connected(out_port) and self.check_acl(packet, 'out', out_port):
                out_iface = PORT1 if out_port == 1 else PORT2
                self.update_stats(packet, 'out', out_port)
                sendp(packet, iface=out_iface, verbose=False)

        if packet.dst.lower() == "ff:ff:ff:ff:ff:ff":
            try_send(2 if input_port == 1 else 1)
        elif packet.dst in self.mac_table:
            dest_port, _ = self.mac_table[packet.dst]
            if dest_port != input_port:
                try_send(dest_port)
        else:
            for out_port in [1, 2]:
                if out_port != input_port:
                    try_send(out_port)

    def handle_packet(self, packet, input_port):
        if packet.haslayer(Ether):
            if self.recent_check(packet):
                return
            if not self.check_acl(packet, 'in', input_port):
                return
            self.update_mac_table(packet.src, input_port)
            self.update_stats(packet, 'in', input_port)
            self.forward_packet(packet, input_port)

    def check_acl(self, packet, direction, port):
        for rule in self.acl_rules:
            if rule['direction'] != direction or rule['port'] != port:
                continue

            if rule['src_mac'] and packet.src.lower() != rule['src_mac'].lower():
                continue
            if rule['dst_mac'] and packet.dst.lower() != rule['dst_mac'].lower():
                continue

            if IP in packet:
                if rule['src_ip'] and packet[IP].src != rule['src_ip']:
                    continue
                if rule['dst_ip'] and packet[IP].dst != rule['dst_ip']:
                    continue

                proto = rule['proto'].upper()
                port_number = int(rule['port_number']) if rule['port_number'] else None

                if proto == "ANY":
                    rule['hits'] += 1
                    return rule['action'] == "ALLOW"

                if proto == "TCP":
                    if not packet.haslayer(TCP):
                        continue
                    if port_number is not None and packet[TCP].sport != port_number and packet[TCP].dport != port_number:
                        continue
                    rule['hits'] += 1
                    return rule['action'] == "ALLOW"

                if proto == "UDP":
                    if not packet.haslayer(UDP):
                        continue
                    if port_number is not None and packet[UDP].sport != port_number and packet[UDP].dport != port_number:
                        continue
                    rule['hits'] += 1
                    return rule['action'] == "ALLOW"

                if proto == "ICMP":
                    if not packet.haslayer(ICMP):
                        continue
                    rule['hits'] += 1
                    return rule['action'] == "ALLOW"

            if rule['src_ip'] or rule['dst_ip'] or rule['proto'] or rule['port_number']:
                continue

            rule['hits'] += 1
            return rule['action'] == "ALLOW"

        return True


    def start_sniffing_iface1(self):
        sniff(prn=lambda pkt: self.handle_packet(pkt, 1), store=False, iface=PORT1)

    def start_sniffing_iface2(self):
        sniff(prn=lambda pkt: self.handle_packet(pkt, 2), store=False, iface=PORT2)

    def port_activity(self):
        while True:
            now = time.time()
            for port in [1, 2]:
                if now - self.port_last_activity[port] > 5:
                    self.port_status[port] = "Disconnected"
                    self.mac_table = {mac: (p, t) for mac, (p, t) in self.mac_table.items() if p != port}
                    self.port_stats[port] = {'in': 0, 'out': 0}
                    for protocol in self.stats:
                        self.stats[protocol]['in'][port-1] = 0
                        self.stats[protocol]['out'][port-1] = 0
            time.sleep(1)

    def start_sniffing(self):
        threading.Thread(target=self.start_sniffing_iface1, daemon=True).start()
        threading.Thread(target=self.start_sniffing_iface2, daemon=True).start()
        threading.Thread(target=self.clean_old, daemon=True).start()
        threading.Thread(target=self.expire_mac_records, daemon=True).start()
        threading.Thread(target=self.port_activity, daemon=True).start()

    def clear_mac_table(self):
        self.mac_table.clear()

    def reset_stats(self):
        for category in self.stats:
            for d in ['in', 'out']:
                self.stats[category][d] = [0, 0]
        for port in self.port_stats:
            self.port_stats[port]['in'] = 0
            self.port_stats[port]['out'] = 0

    def set_mac_expiration_time(self, new_time):
        try:
            self.record_timeout = int(new_time)
        except ValueError:
            pass

    def create_gui(self):
        root = tk.Tk()
        root.title("Naker Switch")
        root.attributes("-fullscreen", False)

        style = ttk.Style(root)
        style.theme_use("clam")
        default_font = ("Arial", 10)
        style.configure("TLabel", font=default_font)
        style.configure("TButton", font=default_font)
        style.configure("Treeview", font=default_font, rowheight=25)
        style.configure("Treeview.Heading", font=("Arial", 10, "bold"))

        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        mac_frame = ttk.LabelFrame(main_frame, text="MAC Table", padding="10")
        mac_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        self.mac_tree = ttk.Treeview(mac_frame, columns=("MAC", "Port", "Lifetime"), show="headings", height=10)
        self.mac_tree.heading("MAC", text="MAC Address")
        self.mac_tree.heading("Port", text="Port")
        self.mac_tree.heading("Lifetime", text="Lifetime (sec)")
        self.mac_tree.column("MAC", width=200)
        self.mac_tree.column("Port", width=50, anchor="center")
        self.mac_tree.column("Lifetime", width=100, anchor="center")
        self.mac_tree.pack(fill=tk.BOTH, expand=True)

        stats1_frame = ttk.LabelFrame(main_frame, text=f"Port 1 - {PORT1}", padding="10")
        stats1_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        self.port1_tree = ttk.Treeview(stats1_frame, columns=("Protocol", "In", "Out"), show="headings", height=10)
        self.port1_tree.heading("Protocol", text="Protocol")
        self.port1_tree.heading("In", text="In")
        self.port1_tree.heading("Out", text="Out")
        self.port1_tree.column("Protocol", width=150)
        self.port1_tree.column("In", width=70, anchor="center")
        self.port1_tree.column("Out", width=70, anchor="center")
        self.port1_tree.tag_configure("overall", font=("Arial", 10, "bold"))
        self.port1_tree.pack(fill=tk.BOTH, expand=True)

        stats2_frame = ttk.LabelFrame(main_frame, text=f"Port 2 - {PORT2}", padding="10")
        stats2_frame.grid(row=0, column=2, sticky="nsew", padx=5, pady=5)
        self.port2_tree = ttk.Treeview(stats2_frame, columns=("Protocol", "In", "Out"), show="headings", height=10)
        self.port2_tree.heading("Protocol", text="Protocol")
        self.port2_tree.heading("In", text="In")
        self.port2_tree.heading("Out", text="Out")
        self.port2_tree.column("Protocol", width=150)
        self.port2_tree.column("In", width=70, anchor="center")
        self.port2_tree.column("Out", width=70, anchor="center")
        self.port2_tree.tag_configure("overall", font=("Arial", 10, "bold"))
        self.port2_tree.pack(fill=tk.BOTH, expand=True)

        status_frame = ttk.Frame(root, padding="10")
        status_frame.pack(fill=tk.X)
        self.port1_status_label = ttk.Label(status_frame, text=f"Port 1 Status: {self.port_status[1]}", font=("Arial", 10, "bold"))
        self.port1_status_label.pack(side=tk.LEFT, padx=20)
        self.port2_status_label = ttk.Label(status_frame, text=f"Port 2 Status: {self.port_status[2]}", font=("Arial", 10, "bold"))
        self.port2_status_label.pack(side=tk.LEFT, padx=20)

        control_frame = ttk.Frame(root, padding="10")
        control_frame.pack(fill=tk.X)
        ttk.Button(control_frame, text="Clear MAC Table", command=self.clear_mac_table).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Reset Statistics", command=self.reset_stats).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Exit", command=root.destroy).pack(side=tk.LEFT, padx=5)

        timer_frame = ttk.Frame(root, padding="10")
        timer_frame.pack(fill=tk.X)
        ttk.Label(timer_frame, text="MAC Address Expiration Timeout (seconds):").pack(side=tk.LEFT, padx=5)
        timer_entry = ttk.Entry(timer_frame, width=10)
        timer_entry.pack(side=tk.LEFT, padx=5)
        timer_entry.insert(0, str(self.record_timeout))
        ttk.Button(timer_frame, text="Set Timeout", command=lambda: self.set_mac_expiration_time(timer_entry.get())).pack(side=tk.LEFT, padx=5)

        acl_frame = ttk.LabelFrame(root, text="ACL Rules", padding="10")
        acl_frame.pack(fill=tk.BOTH, expand=True)

        self.acl_tree = ttk.Treeview(
            acl_frame,
            columns=("Dir", "Port", "Src MAC", "Dst MAC", "Src IP", "Dst IP", "Proto", "Port", "Action", "Hits"),
            show="headings",
            height=5
        )
        for col in self.acl_tree["columns"]:
            self.acl_tree.heading(col, text=col)
            width = 150 if "MAC" in col or "IP" in col else 80
            self.acl_tree.column(col, width=width, anchor="center")
        self.acl_tree.pack(fill=tk.BOTH, expand=True)

        def add_acl_rule():
            rule = {
                "direction": dir_var.get(),
                "port": int(port_var.get()),
                "src_mac": src_mac_var.get() or None,
                "dst_mac": dst_mac_var.get() or None,
                "src_ip": src_ip_var.get() or None,
                "dst_ip": dst_ip_var.get() or None,
                "proto": proto_var.get(),
                "port_number": portnum_var.get() or None,
                "action": action_var.get(),
                "hits": 0
            }
            self.acl_rules.append(rule)
            self.refresh_acl_tree()

        def delete_selected_rule():
            selected = self.acl_tree.selection()
            for item in selected:
                index = self.acl_tree.index(item)
                del self.acl_rules[index]
                self.acl_tree.delete(item)

        def refresh_acl_tree():
            selected = self.acl_tree.selection()
            selected_ids = [self.acl_tree.index(item) for item in selected]
            self.acl_tree.delete(*self.acl_tree.get_children())
            for idx, rule in enumerate(self.acl_rules):
                iid = self.acl_tree.insert("", "end", values=(
                    rule["direction"], rule["port"],
                    rule["src_mac"], rule["dst_mac"], rule["src_ip"], rule["dst_ip"],
                    rule["proto"], rule["port_number"], rule["action"], rule["hits"]
                ))
                if idx in selected_ids:
                    self.acl_tree.selection_add(iid)

        self.refresh_acl_tree = refresh_acl_tree

        input_frame = ttk.Frame(acl_frame)
        input_frame.pack(pady=5)

        dir_var = tk.StringVar(value="in")
        port_var = tk.StringVar(value="1")
        src_mac_var = tk.StringVar()
        dst_mac_var = tk.StringVar()
        src_ip_var = tk.StringVar()
        dst_ip_var = tk.StringVar()
        proto_var = tk.StringVar(value="TCP")
        portnum_var = tk.StringVar()
        action_var = tk.StringVar(value="ALLOW")

        entries = [
            ("Dir", dir_var, ["in", "out"]),
            ("Port", port_var, ["1", "2"]),
            ("Src MAC", src_mac_var),
            ("Dst MAC", dst_mac_var),
            ("Src IP", src_ip_var),
            ("Dst IP", dst_ip_var),
            ("Proto", proto_var, ["TCP", "UDP", "ICMP", "ANY"]),
            ("Port", portnum_var),
            ("Action", action_var, ["ALLOW", "DENY"])
        ]

        for i, (label, var, *opts) in enumerate(entries):
            ttk.Label(input_frame, text=label).grid(row=0, column=i)
            if opts:
                ttk.Combobox(input_frame, textvariable=var, values=opts[0], width=10).grid(row=1, column=i)
            else:
                ttk.Entry(input_frame, textvariable=var, width=17).grid(row=1, column=i)

        ttk.Button(input_frame, text="Add Rule", command=add_acl_rule).grid(row=2, column=0, columnspan=2)
        ttk.Button(input_frame, text="Delete Selected", command=delete_selected_rule).grid(row=2, column=2, columnspan=2)

        def update_gui():
            curr_time = time.time()
            for item in self.mac_tree.get_children():
                self.mac_tree.delete(item)
            for mac, (port, t) in self.mac_table.copy().items():
                lifetime = max(0, self.record_timeout - (curr_time - t))
                self.mac_tree.insert("", "end", values=(mac, port, f"{lifetime:.2f}"))

            for item in self.port1_tree.get_children():
                self.port1_tree.delete(item)
            for protocol, values in self.stats.items():
                self.port1_tree.insert("", "end", values=(protocol, values['in'][0], values['out'][0]))
            self.port1_tree.insert("", "end", values=("Overall", self.port_stats[1]['in'], self.port_stats[1]['out']), tags=("overall",))

            for item in self.port2_tree.get_children():
                self.port2_tree.delete(item)
            for protocol, values in self.stats.items():
                self.port2_tree.insert("", "end", values=(protocol, values['in'][1], values['out'][1]))
            self.port2_tree.insert("", "end", values=("Overall", self.port_stats[2]['in'], self.port_stats[2]['out']), tags=("overall",))

            self.port1_status_label.config(text=f"Port 1 Status: {self.port_status[1]}")
            self.port2_status_label.config(text=f"Port 2 Status: {self.port_status[2]}")

            self.refresh_acl_tree()

            root.after(10, update_gui)

        update_gui()
        root.mainloop()

switch = Switch()
switch.start_sniffing()
switch.create_gui()
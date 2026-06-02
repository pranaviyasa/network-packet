import tkinter as tk
from tkinter import ttk, scrolledtext
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Raw
from datetime import datetime
import threading


# ---------------- Packet Sniffer Class ---------------- #
class NetworkSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Sniffer - Cybersecurity Internship")
        self.root.geometry("900x600")
        self.root.resizable(True, True)

        self.running = False
        self.packet_count = 0

        # -------- Title -------- #
        title = tk.Label(
            root,
            text="Network Packet Sniffer",
            font=("Arial", 18, "bold"),
            fg="blue"
        )
        title.pack(pady=10)

        # -------- Filter Frame -------- #
        filter_frame = tk.Frame(root)
        filter_frame.pack(pady=5)

        tk.Label(filter_frame, text="Protocol Filter:").pack(side=tk.LEFT, padx=5)

        self.filter_var = tk.StringVar(value="all")
        filter_dropdown = ttk.Combobox(
            filter_frame,
            textvariable=self.filter_var,
            values=["all", "tcp", "udp", "icmp"],
            state="readonly",
            width=10
        )
        filter_dropdown.pack(side=tk.LEFT)

        # -------- Buttons -------- #
        button_frame = tk.Frame(root)
        button_frame.pack(pady=10)

        self.start_btn = tk.Button(
            button_frame,
            text="Start Sniffing",
            bg="green",
            fg="white",
            font=("Arial", 10, "bold"),
            command=self.start_sniffing
        )
        self.start_btn.pack(side=tk.LEFT, padx=10)

        self.stop_btn = tk.Button(
            button_frame,
            text="Stop Sniffing",
            bg="red",
            fg="white",
            font=("Arial", 10, "bold"),
            command=self.stop_sniffing,
            state=tk.DISABLED
        )
        self.stop_btn.pack(side=tk.LEFT, padx=10)

        clear_btn = tk.Button(
            button_frame,
            text="Clear Output",
            bg="orange",
            fg="black",
            font=("Arial", 10, "bold"),
            command=self.clear_output
        )
        clear_btn.pack(side=tk.LEFT, padx=10)

        # -------- Output Box -------- #
        self.output_box = scrolledtext.ScrolledText(
            root,
            wrap=tk.WORD,
            width=110,
            height=28,
            font=("Consolas", 10)
        )
        self.output_box.pack(padx=10, pady=10)

    # ---------------- Analyze Packet ---------------- #
    def analyze_packet(self, packet):
        if not self.running:
            return

        self.packet_count += 1
        timestamp = datetime.now().strftime("%H:%M:%S")

        output = "\n" + "─" * 60 + "\n"
        output += f"Packet #{self.packet_count} | Time: {timestamp}\n"
        output += "─" * 60 + "\n"

        # ARP Packet
        if packet.haslayer(ARP):
            arp = packet[ARP]
            operation = "Request" if arp.op == 1 else "Reply"
            output += f"Protocol    : ARP ({operation})\n"
            output += f"Sender IP   : {arp.psrc}\n"
            output += f"Target IP   : {arp.pdst}\n"

        # IP Packet
        elif packet.haslayer(IP):
            ip = packet[IP]
            output += f"Source IP   : {ip.src}\n"
            output += f"Destination : {ip.dst}\n"
            output += f"TTL         : {ip.ttl}\n"
            output += f"Packet Size : {len(packet)} bytes\n"

            # TCP
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                output += "Protocol    : TCP\n"
                output += f"Ports        : {tcp.sport} → {tcp.dport}\n"

            # UDP
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                output += "Protocol    : UDP\n"
                output += f"Ports        : {udp.sport} → {udp.dport}\n"

            # ICMP
            elif packet.haslayer(ICMP):
                output += "Protocol    : ICMP\n"

            # Payload
            if packet.haslayer(Raw):
                raw_data = packet[Raw].load
                try:
                    decoded = raw_data.decode("utf-8", errors="replace")
                    preview = decoded[:100].replace("\n", " ")
                    output += f"Payload     : {preview}\n"
                except:
                    output += "Payload     : Binary Data\n"

        self.output_box.insert(tk.END, output)
        self.output_box.see(tk.END)

    # ---------------- Start Sniffing ---------------- #
    def sniff_packets(self):
        selected_filter = self.filter_var.get()

        sniff(
            prn=self.analyze_packet,
            store=False,
            filter=None if selected_filter == "all" else selected_filter,
            stop_filter=lambda x: not self.running
        )

    def start_sniffing(self):
        self.running = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)

        thread = threading.Thread(target=self.sniff_packets)
        thread.daemon = True
        thread.start()

        self.output_box.insert(
            tk.END,
            "\n[INFO] Packet sniffing started...\n"
        )

    # ---------------- Stop Sniffing ---------------- #
    def stop_sniffing(self):
        self.running = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

        self.output_box.insert(
            tk.END,
            "\n[INFO] Packet sniffing stopped.\n"
        )

    # ---------------- Clear Output ---------------- #
    def clear_output(self):
        self.output_box.delete(1.0, tk.END)


# ---------------- Main ---------------- #
if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkSnifferGUI(root)
    root.mainloop()
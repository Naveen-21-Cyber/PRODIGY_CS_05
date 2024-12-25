from scapy.all import sniff, IP
from tkinter import *
from tkinter import scrolledtext
import threading

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Scapy Packet Sniffer")
        self.root.geometry("900x500")

        # GUI components
        self.text_area = scrolledtext.ScrolledText(self.root, wrap=WORD, font=("Courier", 10))
        self.text_area.pack(fill=BOTH, expand=1)

        self.start_button = Button(self.root, text="Start Sniffing", command=self.start_sniffing, bg="green", fg="white")
        self.start_button.pack(side=LEFT, padx=10, pady=10)

        self.stop_button = Button(self.root, text="Stop Sniffing", command=self.stop_sniffing, bg="red", fg="white", state=DISABLED)
        self.stop_button.pack(side=RIGHT, padx=10, pady=10)

        self.sniffing = False
        self.sniffer_thread = None

    def start_sniffing(self):
        self.sniffing = True
        self.start_button.config(state=DISABLED)
        self.stop_button.config(state=NORMAL)
        self.sniffer_thread = threading.Thread(target=self.sniff_packets, daemon=True)
        self.sniffer_thread.start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.config(state=NORMAL)
        self.stop_button.config(state=DISABLED)

    def sniff_packets(self):
        try:
            sniff(prn=self.process_packet, stop_filter=lambda x: not self.sniffing)
        except PermissionError:
            self.text_area.insert(END, "Permission Error: Run the script as Administrator.\n")
        except Exception as e:
            self.text_area.insert(END, f"Error: {e}\n")

    def process_packet(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            protocol = packet[IP].proto
            payload = bytes(packet[IP].payload).decode('utf-8', errors='replace')[:50]  # First 50 bytes

            self.text_area.insert(END, f"Source IP: {src_ip}\n")
            self.text_area.insert(END, f"Destination IP: {dst_ip}\n")
            self.text_area.insert(END, f"Protocol: {self.get_protocol_name(protocol)}\n")
            self.text_area.insert(END, f"Payload: {payload}\n")
            self.text_area.insert(END, "-" * 50 + "\n")
            self.text_area.see(END)

    @staticmethod
    def get_protocol_name(protocol_num):
        protocols = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
        }
        return protocols.get(protocol_num, f"Unknown ({protocol_num})")


if __name__ == "__main__":
    root = Tk()
    app = PacketSnifferApp(root)
    root.mainloop()

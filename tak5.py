from scapy.all import sniff, IP, TCP, UDP
from pynput import keyboard
import threading

stop_sniffing = False  # Flag to stop the loop

# Function to print packet details
def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst

        if TCP in packet:
            proto = "TCP"
        elif UDP in packet:
            proto = "UDP"
        else:
            proto = "Other"

        print(f"🔹 {proto} | From {src} → {dst}")

# Function to listen for ESC key
def listen_for_esc():
    def on_press(key):
        global stop_sniffing
        if key == keyboard.Key.esc:
            stop_sniffing = True
            print("🛑 ESC pressed! Stopping packet capture...")
            return False
    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()

# Start keyboard listener in a background thread
esc_thread = threading.Thread(target=listen_for_esc)
esc_thread.start()

# Sniff loop that checks the stop flag every 2 seconds
print("📡 Sniffing... Press ESC to stop.")
while not stop_sniffing:
    sniff(filter="ip", prn=process_packet, timeout=2)

print("✅ Packet sniffing stopped.")

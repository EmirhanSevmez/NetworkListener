from scapy.all import sniff, TCP, Raw, IP


def listen_packets(): # sniff the packets
    sniff(filter="tcp port 80 or tcp port 443",store=False,prn=analyze_packets) # sniff the packets

def analyze_packets(packet): # analyze the packets
    if packet.haslayer(TCP) and packet.haslayer(Raw) and packet[TCP].dport == 80: # if the packet has TCP layer and Raw layer and destination port is 80
        try:
            httpData= packet[Raw].load.decode(errors='ignore') # decode the packet
            if httpData.startswith(("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS")): # if the packet starts with GET, POST, PUT, DELETE, HEAD, OPTIONS
                print("HTTP Request Detected") # print the message
                print(f"Source IP:{packet[IP].src} Destination IP:{packet[IP].dst}") # print the source and destination IP
                print(f"HTTP Request:{httpData}") # print the HTTP request
                print("------------------------------------------------------------")
        except:
            pass

    elif packet.haslayer(TCP) and packet.haslayer(Raw) and packet[TCP].dport == 443: # if the packet has TCP layer and Raw layer and destination port is 443
        print("HTTPS Request Detected") # print the message
        print(f"Source IP:{packet[IP].src} Destination IP:{packet[IP].dst}") # print the source and destination IP
        print("HTTPS request detected, but HTTPS data is encrypted and cannot be decoded") # print the message
        print("------------------------------------------------------------")
            

print("Network Listener Started")
listen_packets()
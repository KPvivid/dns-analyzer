import threading
import time
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import sniff, DNS, DNSQR
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
from collections import Counter
import os

# Initialize an empty list to store all captured packets
all_packets = []
lock = threading.Lock()  # Create a lock to synchronize access to all_packets
stop_capture_event = threading.Event()  # Event to signal the live capture thread to stop

def parse_dns(packets):
    main_domains = []

    for pkt in packets:
        if DNS in pkt and pkt.haslayer(DNSQR):
            name = pkt[DNSQR].qname.decode('utf-8', errors='replace')
            main_domains.append(name)

    return main_domains

def visualize_dns(main_domains):
    if not main_domains:
        return

    # Count occurrences of each main domain
    domain_counter = Counter(main_domains)

    # Get the top 10 domains and aggregate others
    top_domains = domain_counter.most_common(10)
    other_count = sum(domain_counter.values()) - sum(count for domain, count in top_domains)

    # Extract data for the pie chart
    labels = [domain if count > 0 else 'Other' for domain, count in top_domains] + ['Other']
    values = [count for domain, count in top_domains] + [other_count]

    # Set a custom color cycle for the pie chart
    colors = plt.cm.Paired.colors

    # Plot the pie chart with a shadow, explode the 'Other' slice, and add percentage labels
    plt.pie(values, labels=labels, autopct='%1.1f%%', startangle=140, shadow=True, colors=colors, explode=[0.1] + [0] * len(top_domains))
    plt.axis('equal')  # Equal aspect ratio ensures that the pie chart is circular.

    # Set the title with an increased font size
    plt.title('Top 10 DNS Requests and Others', fontsize=16)

    # Add a legend to identify each slice
    plt.legend(labels, loc='upper right', bbox_to_anchor=(1, 0.8))

def capture_live_packets():
    global all_packets
    try:
        while not stop_capture_event.is_set():
            live_packets = sniff(filter="udp port 53", count=1)
            with lock:
                all_packets.extend(live_packets)
    except Exception as e:
        print(f"An error occurred during live capture: {e}")

def update_visualization(frame):
    with lock:
        # Clear the previous pie chart
        plt.clf()

        # Process and visualize the entire list
        main_domains = parse_dns(all_packets)
        visualize_dns(main_domains)

# Set up the animation
animation = FuncAnimation(plt.gcf(), update_visualization, cache_frame_data=False, interval=1000)  # Update every 10 seconds

# REPL for user interaction
while not stop_capture_event.is_set():
    choice = input("> ")

    if choice.lower() == 'q':
        stop_capture_event.set()  # Signal the live capture thread to stop
        break
    elif choice.lower() == 'file':
        pcap_file = input("Enter the name of the PCAP file: ")
        try:
            # Read the pcap file and append packets to the list
            packets = sniff(offline=pcap_file)
            with lock:
                all_packets.extend(packets)
                # Process and visualize the entire list
                main_domains = parse_dns(all_packets)
                visualize_dns(main_domains)
        except FileNotFoundError:
            print(f"File '{pcap_file}' not found. Please enter a valid file name.")
        except Exception as e:
            print(f"An error occurred: {e}")

        plt.show()
        stop_capture_event.set() 
    elif choice.lower() == 'live':
        # Start the live capture thread
        stop_capture_event.clear()  # Reset the event in case it was set previously
        live_capture_thread = threading.Thread(target=capture_live_packets)
        live_capture_thread.start()
        print("Live capture started")
        plt.show()
        stop_capture_event.set() 
        live_capture_thread.join()  # Wait for the live capture thread to finish
        print("Finish Capturing", len(all_packets), "DNS packets")
    else:
        print("Invalid choice. Please enter 'file', 'live', or 'q'.")
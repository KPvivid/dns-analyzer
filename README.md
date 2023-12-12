# DNS Traffic Analyzer for Network Monitoring - Project Writeup

## Introduction

The goal of this project was to develop a DNS traffic analyzer capable of monitoring live DNS requests and visualizing the top DNS domains. The tool provides insights into network activity by capturing and analyzing DNS packets in real-time or from a provided PCAP file. The primary achievement is the creation of a user-friendly tool that facilitates the understanding of DNS traffic patterns on a network.

## Design/Implementation

### Major Components:

1. **Packet Capture:**
   - Utilizes the `scapy` library to capture DNS packets either live or from a PCAP file.
   - The `sniff` function is employed with filters to capture DNS packets on UDP port 53.

2. **Data Processing:**
   - DNS packets are parsed to extract the queried domain names (`DNSQR` layer).
   - The parsed data is stored in a global list (`all_packets`) with thread synchronization using a lock.

3. **Visualization:**
   - Utilizes `matplotlib` for visualizing the data in a pie chart format.
   - The top 10 DNS domains are identified, and the rest are aggregated into an "Other" category.
   - Custom colors are applied to enhance visual appeal.

4. **User Interaction:**
   - A REPL (Read-Eval-Print Loop) is implemented for user interaction.
   - Options include live capture, reading from a PCAP file, and exiting the program.

5. **Threading:**
   - A separate thread (`live_capture_thread`) is used for live packet capture to avoid blocking the main thread.
   - Threading is synchronized using a lock to ensure data consistency.

### Overview:

The program employs a modular design, separating packet capture, data processing, and visualization. It allows users to choose between live capture and analyzing packets from a PCAP file. The pie chart visualization provides an intuitive representation of the top DNS domains and their relative proportions.

## Discussion/Results

### Results:

Upon running the program, users can interactively choose between live capture and PCAP file analysis. The pie chart dynamically updates, offering a visual representation of the top DNS domains in real-time. The "Other" category aggregates less frequent domains for clarity.

### Challenges:

1. **Threading and Synchronization:**
   - Ensuring thread safety for packet storage (`all_packets`) required careful consideration to prevent data corruption.
   
2. **Live Capture Interruption:**
   - Managing the live capture thread and ensuring it stops promptly upon user request without data loss posed a challenge.

### Logs/Screenshots:



## Conclusions/Future Work

### Learning Outcomes:

The project provided valuable experience in:
   - Working with packet capture and analysis using the `scapy` library.
   - Implementing multi-threading for live capture without blocking the main thread in python.
   - Creating dynamic visualizations for real-time data updates in python.

### Project Evaluation:

Overall, the project was successful in meeting its objectives. The tool effectively captures and analyzes DNS traffic, providing a clear visualization of network activity.

### Future Work:

If continued, the project could be expanded by:
   - Adding more visualization options (e.g., bar charts, line charts) for a comprehensive analysis.
   - Implementing statistical analysis to identify anomalies or suspicious behavior in DNS traffic.
   - Adding option for intercepting and blocking DNS request to unwanted websites

In conclusion, the DNS Traffic Analyzer serves as a valuable tool for network administrators and security professionals, offering insights into DNS traffic patterns and facilitating informed decision-making. The project's modular design allows for future enhancements and improvements.

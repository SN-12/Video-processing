
from matplotlib import pyplot as plt
import scapy.all as sp
import dnslib
import random
import pandas as pd

YT_DOMAINS = ["youtube", "googlevideo", "ytimg", "youtube-nocookie"]

youtube_ips = []

pcap_file = "Youtube.pcap"


def get_youtube_ips(pcap_file):
  with sp.PcapReader(pcap_file) as trace:
    for packet in trace:
      # DNS Packet
      if packet.haslayer(sp.UDP) and packet[sp.UDP].sport == 53:
        # Get DNS data
        raw = sp.raw(packet[sp.UDP].payload)
        # Process the DNS query
        dns = dnslib.DNSRecord.parse(raw)
        # Iterate over answers
        for a in dns.rr:
          # Check if it's a domain of interest (domain.com)
          question = str(a.rname)
          if any(s in question for s in YT_DOMAINS):
            # Check if it's an answer
            if a.rtype == 1 or a.rtype == 28:
              print("Query {} is a Youtube one. Appending IP {} to Youtube IPs".format(question, a.rdata))
              youtube_ips.append(str(a.rdata))
            # youtube_ips object:
  print("Youtube IPs: {}".format(youtube_ips))
  return youtube_ips
            
            
def counters():
  return {"in_pkts": 0, "out_pkts": 0, "in_bytes": 0, "out_bytes": 0}


def get_flow_traffic_corrected(pcap_file, youtube_ips):
  traffic_data = []
  interval = 1.0
  
  with sp.PcapReader(pcap_file) as trace:
    start_time = 0
    end_time = -1
    slot_dict = {"start" : start_time, "end": end_time, "flows": {}}
    print("Processing slot {}-{}".format(start_time, end_time))
    for packet in trace:
      if not packet.haslayer(sp.IP):
        continue
      if packet[sp.IP].time > end_time:
        #reset your countes 
        traffic_data.append(slot_dict)
        if start_time == 0:
          start_time = packet[sp.IP].time
        else:
          start_time = end_time
        end_time = start_time + interval
        slot_dict = {"start" : start_time, "end": end_time, "flows": {}}
        print("Processing slot {}-{}".format(start_time, end_time))
      
      # If it belongs to Youtube's traffic
      if packet.haslayer(sp.TCP)  and (packet[sp.IP].src in youtube_ips or packet[sp.IP].dst in youtube_ips):
        key = ''
        # identify the direction
        if packet[sp.IP].src in youtube_ips:
          dir = 1
          key = "{}:{}:{}:{}:TCP".format(packet[sp.IP].src, packet[sp.TCP].sport, packet[sp.IP].dst, packet[sp.TCP].dport)

        elif packet[sp.IP].dst in youtube_ips:
          dir = 0
          key = "{}:{}:{}:{}:TCP".format(packet[sp.IP].dst, packet[sp.TCP].dport, packet[sp.IP].src, packet[sp.TCP].sport)


      # UPD traffic:
      if packet.haslayer(sp.UDP) and (packet[sp.IP].src in youtube_ips or packet[sp.IP].dst in youtube_ips):
        key = ''
        # identify the direction
        if packet[sp.IP].src in youtube_ips:
          dir = 1
          key = "{}:{}:{}:{}:UDP".format(packet[sp.IP].src, packet[sp.UDP].sport, packet[sp.IP].dst,
                                           packet[sp.UDP].dport)

        elif packet[sp.IP].dst in youtube_ips:
          dir = 0
          key = "{}:{}:{}:{}:UDP".format(packet[sp.IP].dst, packet[sp.UDP].dport, packet[sp.IP].src,
                                           packet[sp.UDP].sport)
      
        
        if key not in slot_dict["flows"]:
          slot_dict["flows"][key] = counters()
        
        if dir == 1:
          slot_dict["flows"][key]['in_pkts'] += 1
          slot_dict["flows"][key]['in_bytes'] += packet[sp.IP].len
        else:
          slot_dict["flows"][key]['out_pkts'] += 1
          slot_dict["flows"][key]['out_bytes'] += packet[sp.IP].len
  return traffic_data
        
def plot_throughput(traffic):
  flows = {}
  fig, ax = plt.subplots()

  for time_slot in traffic:
    for flowId in time_slot["flows"]:
      if flowId not in flows:
        flows[flowId] = {"time": [], "throughput": []}
        
      flows[flowId]["time"].append(time_slot["end"])
      flows[flowId]["throughput"].append(time_slot["flows"][flowId]["in_bytes"] / (time_slot["end"] - time_slot["start"])*128)
      
  for flowId in flows:
    print("Adding to plot {} {}".format(flows[flowId]["time"], flows[flowId]["throughput"]))

    ax.plot(flows[flowId]["time"], flows[flowId]["throughput"], color=[random.random(), random.random(), random.random()], label='Flow'+flowId,linewidth=2)


  plt.xlabel('time(Second)')
  plt.ylabel('Throughput(Kbps)')
  ax.legend(loc= 'upper right')
  plt.show()


def main():
  youtube_ips = get_youtube_ips("Youtube.pcap")
  traffic = get_flow_traffic_corrected("Youtube.pcap", youtube_ips)
  plot_throughput(traffic)


if __name__=="__main__":
  main()











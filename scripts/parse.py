from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
import matplotlib.pyplot as plt
from scapy.all import rdpcap, UDP

@dataclass
class RDMAPacket:
    opcode: int
    dst_qp: int
    seq_num: int
    time: Decimal

    def to_csv(self):
        return ','.join(map(str, [self.opcode, self.dst_qp, self.seq_num, self.time]))

    @staticmethod
    def from_csv(line: str):
        paras = line.strip().split(',')
        try:
            return RDMAPacket(int(paras[0]), int(paras[1]), int(paras[2]), Decimal(paras[3]))
        except ValueError as ve:
            print(f'Error format: {line}')

def read_rdma_packets(file: str) -> list[RDMAPacket]:
    """
    读取数据文件并解析成 RDMA 包列表。若为pcap文件，则同时将其保存为csv文件
    """
    rdma_packets = []
    qp2seq_map = defaultdict(int)
    if file.endswith('.pcap'):
        print("Reading PCAP file...")
        packets = rdpcap(file)
        print("Finished reading PCAP file")
        with open('data.csv', 'w') as csv_file:
            for packet in packets:
                if packet.haslayer(UDP):
                    udp_payload = packet[UDP].payload
                    if udp_payload.haslayer("Raw"):
                        raw_data = bytes(udp_payload["Raw"].load)
                        destination_qp = int.from_bytes(raw_data[5:8], byteorder="big")
                        sequence_number = int.from_bytes(raw_data[9:12], byteorder="big")
                        opcode = int.from_bytes(raw_data[0:1], byteorder="big")
                        if opcode == 17:
                            continue
                        rdma_packet = RDMAPacket(opcode, destination_qp, sequence_number, packet.time)
                        csv_file.write(rdma_packet.to_csv() + '\n')
                        rdma_packets.append(rdma_packet)
    elif file.endswith('.csv'):
        print("Reading CSV file...")
        with open(file, 'r') as csv_file:
            for line in csv_file.readlines():
                if line.strip():
                    rdma_packet = RDMAPacket.from_csv(line)
                    
                    if rdma_packet.opcode == 17:
                        continue
                    rdma_packets.append(rdma_packet)
        print("Finished reading CSV file")
    else:
        raise ValueError("Unsupported file format. Only .pcap or .csv are supported.")
    return rdma_packets

def analyze_rdma_retransmit(rdma_packets: list[RDMAPacket]) -> list[Decimal]:
    """
    分析 RDMA 包列表并检测重传事件。
    """
    qp2seq_map = defaultdict(int)
    retransmit_event = []
    for packet in rdma_packets:
        if packet.seq_num < qp2seq_map[packet.dst_qp] and packet.opcode != 17:
            print(packet, qp2seq_map[packet.dst_qp])
            retransmit_event.append(packet.time)
        qp2seq_map[packet.dst_qp] = packet.seq_num
    return retransmit_event

def plot_retransmit_events_histogram(retransmit_event):
    # 将Decimal对象转换为浮点数，以便进行绘图
    time_values = [float(event) for event in retransmit_event]
    
    # 绘制直方图
    plt.figure(figsize=(10, 6))
    plt.hist(time_values, bins=int((time_values[-1] - time_values[0])*100), edgecolor='black', alpha=0.7)
    
    # 设置图表标签和标题
    plt.title("Histogram of Retransmit Events Over Time")
    plt.xlabel("Time (seconds)")
    plt.ylabel("Number of Retransmit Events")
    plt.grid(True, linestyle='--', alpha=0.5)
    plt.savefig('retransmit.png')

# 示例调用
packets = read_rdma_packets('data.csv')
retransmit_event = analyze_rdma_retransmit(packets)
print(retransmit_event[0:20])
plot_retransmit_events_histogram(retransmit_event)

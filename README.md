# Editcap-libpcap
Remove packets with duplicate payload values from the captured data

设计思路：
1. 读取pcap文件，获取所有数据包
2. 解析数据包，获取RTP数据包
3. 将RTP数据包的seq和ssrc存入map
4. 遍历数据包，如果数据包的seq和ssrc在map中，则删除该数据包
5. 将处理后的数据包写入新的pcap文件

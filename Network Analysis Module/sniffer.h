pcap_t* open_pcap_socket(char* device, const char* bpfstr);
void capture_loop(pcap_t* pd, int packets, pcap_handler func);
void myPacketParser(u_char *user, struct pcap_pkthdr *packethdr, u_char *packetptr);
void bailout(int signo);
int sniffer();

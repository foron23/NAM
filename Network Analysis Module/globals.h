#include <pthread.h>
#include "pcap.h"
#include "circularBuffer.h"


extern CircBuf_Flow buf;
extern CircBuf_Pkt pkt_buf;

extern struct pcap_stat curr_stats, stats;
extern int port;
extern char* host;
extern int debug;

extern int packets, c, i;
extern char interface[256], bpfstr[256];

extern pcap_t* pd;
extern int linkhdrlen;

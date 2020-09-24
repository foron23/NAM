
#include <time.h>
#include "dataStructures.h"

#define CIRCBUFSIZE 100
#define MAXLEN 4096


typedef struct CircBuf_Flow
{
  int head;
  int tail;
  int size;
  flow connections[CIRCBUFSIZE];
} CircBuf_Flow;

typedef struct CircBuf_Pkt
{
  int head;
  int tail;
  int size;
  u_char packets[MAXLEN];
} CircBuf_Pkt;

void CircBuf_Init_Flow();
void CircBuf_Init_Pkt();
int CircBuf_Flow_push(flow newFlow, directional_info extra_info, struct timespec time);
flow CircBuf_Flow_pop();
int CircBuf_Pkt_push(u_char *packetptr);
u_char* CircBuf_Pkt_pop();
int CircBuf_Print();

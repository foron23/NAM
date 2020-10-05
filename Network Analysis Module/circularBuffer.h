
#include <time.h>
#include "dataStructures.h"
#include <stdint.h>

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
  uint8_t* packets[MAXLEN];

} CircBuf_Pkt;


void CircBuf_Init_Flow();
void CircBuf_Init_Pkt();
int CircBuf_Flow_push(flow newFlow, directional_info extra_info, struct timespec time);
flow CircBuf_Flow_pop();
int CircBuf_Pkt_push(uint8_t *packetptr);
uint8_t* CircBuf_Pkt_pop();
int CircBuf_Flow_Print();
void CircBuf_Finish();

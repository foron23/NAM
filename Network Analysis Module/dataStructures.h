#ifndef _DATA_STRUCTURES
#define _DATA_STRUCTURES

typedef struct sample_data
{
  signed int src_numPackets, dst_numPackets;
  signed int src_totalBytes, dst_totalBytes;
  signed int sttl, dttl;
  float s_load, d_load;
  signed int s_loss;
  signed int tcp_window; //source
  double s_inpkt;
  double total_arrival_time;
  struct timespec first_tmp;
  struct timespec current_tmp_src;
  struct timespec current_tmp;  //para el calculo final de tiempo
  float s_mean, d_mean;
  signed int http_resp_size;
  signed int same_src_and_dst_ip_ct;
  signed int same_src_ip_and_dst_pt_ct;
} sample_data;


typedef struct flow
{
  char f_srcip[256],f_dstip[256];
  signed int f_srcPort, f_dstPort;
  char* protocol;// tengo que cambiarlo por un mapeo de int (enum)
  sample_data data;
} flow;


typedef struct directional_info
{
  int byteCount;
  int ttl;
  int loss;
}directional_info;



/*
•  Destination packet count.
•  Source bytes.
•  Source TTL.
•  Destination TTL.
•  Source load.
•  Destination Load.
•  Source loss.
•  Source inter-arrival packet time.
•  Source TCP window advertisement.
•  Mean flow packet size transmitted by source.
•  Mean flow packet size transmitted by destination.
•  The content size of the data transferred from a HTTP service.
•  Number of connections with the same source address and destination port in 100 connections according to the last time.
•  Number of connections with the same source address and destination address in 100 connections according to the last time.
*/
typedef struct Sample
{

  signed int src_numPackets, dst_numPackets;
  signed int src_totalBytes;
  signed int sttl, dttl;
  float s_load, d_load;
  signed int s_loss;
  float s_inpkt;
  signed int tcp_window; //source
  float s_mean, d_mean;
  signed int http_resp_size;
  signed int same_src_and_dst_ip_ct;
  signed int same_src_ip_and_dst_pt_ct;
} Sample;

#endif

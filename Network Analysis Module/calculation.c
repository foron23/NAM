#include <time.h>
#include <string.h>

//#include "dataStructures.h"
//#include "circularBuffer.h"
#include "globals.h"


double calculate_time(struct timespec t1, struct timespec t2)
{
  long seconds = t2.tv_sec - t1.tv_sec;
  long ns = t2.tv_nsec - t1.tv_nsec;

  if (t1.tv_nsec > t2.tv_nsec)  // clock underflow
  {
     --seconds;
     ns += 1000000;
   }
 return (double)seconds*1000 + (double)ns/(double)1000000;
}

//Introduciendo un flow devuelve el flow con la informacion de los calculos completa
flow Calculate_Features(flow thisFlow)
{
    int i;
    int same_src_and_dst_ip = 0;
    int same_src_ip_and_dst_pt = 0;
    flow bufElement;
    double total_time;

    for(i=0; i< buf.size; i++)
    {
      bufElement = buf.connections[i];
      if(strcmp(bufElement.f_srcip,thisFlow.f_srcip) == 0 && strcmp(bufElement.f_dstip,thisFlow.f_dstip) == 0)
        same_src_and_dst_ip++;
      if(strcmp(bufElement.f_srcip,thisFlow.f_srcip) == 0 &&  bufElement.f_dstPort == thisFlow.f_dstPort)
        same_src_ip_and_dst_pt++;
    }
    total_time = calculate_time(thisFlow.data.first_tmp, thisFlow.data.current_tmp);
    //printf("total time %f, sinpkt %f\n", total_time,thisFlow.data.total_arrival_time);

    //avoid inf values
    if(total_time==0.0)
      total_time = 1.0;

    thisFlow.data.s_inpkt = thisFlow.data.total_arrival_time/thisFlow.data.src_numPackets;
    thisFlow.data.s_mean = (float)thisFlow.data.src_totalBytes/(float)thisFlow.data.src_numPackets;
    thisFlow.data.d_mean = (float)thisFlow.data.dst_totalBytes/(float)thisFlow.data.dst_numPackets;

    //avoid nan values
    if(thisFlow.data.dst_numPackets == 0)
      thisFlow.data.d_mean = 0.0;

    thisFlow.data.s_load = (float)thisFlow.data.src_totalBytes/total_time;
    thisFlow.data.d_load = (float)thisFlow.data.dst_totalBytes/total_time;
    thisFlow.data.same_src_and_dst_ip_ct = same_src_and_dst_ip;
    thisFlow.data.same_src_ip_and_dst_pt_ct = same_src_ip_and_dst_pt;


    return thisFlow;
}

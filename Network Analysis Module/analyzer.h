
int fetch_flow(flow thisFlow );
void updateFlow_src(flow newFlow, directional_info extra_info ,int index, struct timespec time);
void updateFlow_dst( flow newFlow,directional_info extra_info, int index, struct timespec time);
int isReversed(flow thisFlow, flow newFlow);
int PacketAnalyzer();

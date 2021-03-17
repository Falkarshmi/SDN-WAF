from pox.core import core
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr
import pox.openflow.libopenflow_01 as of
from datetime import datetime

suspicious_strings = ["union+select","order+by","or =","1,2,3","%20union%20all%20select%20","union select","union all select","union+all+select"]
def http_handler(event):
    tcp_packet = event.parsed.find('tcp') 
    if tcp_packet is None:
        return
    elif (tcp_packet.dstport == 80):
      IP = event.parsed.find('ipv4')
      ipaddr = IP.dstip
      print(ipaddr)
      if ipaddr == '10.0.0.4':
        packet = event.parsed
        tcpbytes = tcp_packet.pack()
        packt = tcpbytes.lower()
        print(packt)
        for i in suspicious_strings:
           if packt.find(i) != -1:
              detection_time = str(datetime.now())
              print("String", i ," has been found ! <-> SQL Injection. At the time: ", detection_time)

              IP = event.parsed.find('ipv4')
              ipaddr = IP.srcip
              msg = of.ofp_flow_mod()
              msg.match.dl_type = 0x800
              msg.match.dl_src = packet.src
              msg.match.nw_proto = 6
              msg.match.tp_dst = tcp_packet.dstport
              msg.idle_timeout = 3600
              msg.hard_timeout = 5400
              for connection in core.openflow.connections:
               connection.send(msg)
               core.getLogger("blocker").debug("flow has been installed for %s with destination port %i", IP.srcip, tcp_packet.dstport)
               core.getLogger("blocker").debug("Blocked Suspicious packet from port %s to port %s", tcp_packet.srcport, tcp_packet.dstport)
           else:
               msg = of.ofp_packet_out()
               msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
               msg.data = event.ofp
               msg.in_port = event.port
               for connection in core.openflow.connections:
                   connection.send(msg)
               event.halt = True
    else: 
         return

def launch():
    core.openflow.addListenerByName("PacketIn", http_handler, priority = 10000)

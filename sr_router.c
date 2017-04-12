/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */

  /*get the type of the packet*/
  uint16_t ARP_OR_IP = ethertype(packet);

  /*get the current interface*/
  struct sr_if* iface = sr_get_interface(sr, interface);
  sr_ethernet_hdr_t* e_hdr = (sr_ethernet_hdr_t*)packet;

  /*if packet is a ARP packet, call helper method to handle ARP packet*/
  if(ARP_OR_IP == ethertype_arp)
  {
    sr_arp_hdr_t* a_hdr = (sr_arp_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t));
    /*check if the ARP packet is destinated for this router, if not, do nothing*/
    if(iface->ip == a_hdr->ar_tip && len >= sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t))
    {
      sr_handleARP(sr, packet, len, interface);
    }
  }
  /*if packet is a IP packet, call helper method to handle IP packet*/
  else if(ARP_OR_IP == ethertype_ip)
  {
      sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t));
      /*check if the length of the packet is okay*/
      if(len >= sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t))
      {
        sr_handlIP(sr, packet, len, interface);
      } 
  }
  /*else the packet is not ARP or IP, then do nothing*/
  else
  {
    fprintf(stderr, "wrong packet type, should not happened ! \n");
    /*do nothing*/
  }

}/* end sr_ForwardPacket */


/*---------------------------------------------------------------------
 * Method: sr_handleARP
 * Scope:  Global
 *
 * This method is called each time the router receives an ARP on the
 * interface.  Inside this method, there will handle two part, both
 * ARP reply and ARP request. 
 *---------------------------------------------------------------------*/
void sr_handleARP(struct sr_instance* sr,
                 uint8_t * packet,
                 unsigned int len,
                 char* interface)
{
    /*get the current interface*/
    struct sr_if* iface = sr_get_interface(sr, interface);
    /*create the ethernet header and arp header*/
    sr_ethernet_hdr_t* e_hdr = 0;
    sr_arp_hdr_t*       a_hdr = 0;

    /*get the ethernet header from start of the packet*/
    e_hdr = (sr_ethernet_hdr_t*)packet;
    /*get the arp header, which is after the ethernet header in the packet pointer*/
    a_hdr = (sr_arp_hdr_t*)(packet+sizeof( sr_ethernet_hdr_t));

    /*get the opcode of arp*/
    uint16_t ARP_OPcode = ntohs(a_hdr->ar_op);

    /*if the ARP is a request*/
    if(ARP_OPcode == arp_op_request)
    {
      uint8_t* requestP = malloc(sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t));
      /*create the ethernet header and arp header*/
      sr_ethernet_hdr_t* e_hdr_new = (sr_ethernet_hdr_t*)requestP;
      sr_arp_hdr_t*       a_hdr_new = (sr_arp_hdr_t*)(requestP+sizeof(sr_ethernet_hdr_t));
      
      /*copy all the ethernet header to the new packet ethernet header
       * ether_type, dhost, shost
       */
      e_hdr_new->ether_type = e_hdr->ether_type;
      memcpy(e_hdr_new->ether_dhost, e_hdr->ether_shost, ETHER_ADDR_LEN);
      memcpy(e_hdr_new->ether_shost, iface->addr, ETHER_ADDR_LEN);

      /*change the arp header
       * sender ip becomes current interface's ip
       * sender mac address becomes current interface's mac address
       * destination ip becomes the previous sender ip
       * destination mac address becomes the previous sender mac address
       * the rest stay the same
       */
      a_hdr_new->ar_hrd = a_hdr->ar_hrd;
      a_hdr_new->ar_pro = a_hdr->ar_pro;
      a_hdr_new->ar_hln = a_hdr->ar_hln;
      a_hdr_new->ar_pln = a_hdr->ar_pln;
      a_hdr_new->ar_op = htons(arp_op_reply);
      memcpy(a_hdr_new->ar_sha, iface->addr, ETHER_ADDR_LEN);
      a_hdr_new->ar_sip = iface->ip;
      memcpy(a_hdr_new->ar_tha, a_hdr->ar_sha, ETHER_ADDR_LEN);
      a_hdr_new->ar_tip = a_hdr->ar_sip;

      /*reply the arp request packet*/
      sr_send_packet(sr, requestP, sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t), iface->name);

    }
    /*the ARP is a reply*/
    else
    {
      /*insert the entry into APR cache using method in sr_arpache*/
      struct sr_arpreq * entry = sr_arpcache_insert(&sr->cache, a_hdr->ar_sha, a_hdr->ar_sip);

      /*if the request queue does not contain this ARP, then do nothing*/
      if(entry == NULL)
      {
        return;
      }
      /*get the outstanding packet queue */
      struct sr_packet* outstandingP = entry->packets;

      /*keep looping until there is no outstanding packets waiting for this reply, and
       *send all outstanding packets in the ARP queue 
       */
      while(outstandingP)
      {
        /*get the raw ethernet frame*/
        uint8_t* outP = outstandingP->buf;
        /*create the ethernet header and arp header*/
        sr_ethernet_hdr_t* e_hdr_new = (sr_ethernet_hdr_t*)outP;
        sr_ip_hdr_t*    ip_hdr_new = (sr_ip_hdr_t*)(outP+sizeof(sr_ethernet_hdr_t));

        /*give the value to ethernet destination mac address using the reply ARP's sourse mac address
         *since the ARP is a reply, the source mac address of that ARP will be the destination where
         *we want to send the outstanding packets 
         */
        memcpy(e_hdr_new->ether_dhost, a_hdr->ar_sha, ETHER_ADDR_LEN);
        memcpy(e_hdr_new->ether_shost, iface->addr, ETHER_ADDR_LEN);

        /*recompute the checksum of the entire packet*/
        ip_hdr_new->ip_sum = 0;
        uint16_t newCheckSum = 0;
        newCheckSum = cksum(ip_hdr_new, sizeof(sr_ip_hdr_t));
        ip_hdr_new->ip_sum = newCheckSum;

        /*send the outstanding packet*/
        sr_send_packet(sr, outP, outstandingP->len, iface->name);

        /*move the pointer to next entry in the queue*/
        outstandingP = outstandingP->next;
      }
      /*free up the memory allocate for that entry*/
      sr_arpreq_destroy(&sr->cache, entry);
    }
}

/*---------------------------------------------------------------------
 * Method: sr_handleIP
 * Scope:  Global
 *
 * This method is called each time the router receives an Ip packet on the
 * interface. 
 *---------------------------------------------------------------------*/
void sr_handlIP(struct sr_instance* sr,
                 uint8_t * packet,
                 unsigned int len,
                 char* interface)
{
    
    /*get the the ip header*/
    /* sr_ethernet_hdr_t* e_hdr = (sr_ethernet_hdr_t*)packet;*/
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t));
    /*get the current interface*/
    struct sr_if* iface = sr_get_interface(sr, interface);

    /*get the checksum value from the ip sum field*/
    uint16_t cksumOld = ip_hdr->ip_sum;

    /*recompute the check sum*/
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

    /*if check sum value get from the ip header is not the same as what we just calculated
     *return 
     */
    if(ip_hdr->ip_sum != cksumOld)
    {
      fprintf(stderr, "check sum is incorrect\n");
      return;
    }

    /*check the version should be ipv4*/
    if(ip_hdr->ip_v != (unsigned int)4)
    {
      fprintf(stderr, "version is incorrect\n");
      return;
    }

    /*get the interface list*/
    struct sr_if* if_walker = sr->if_list;

    /*loop through all interface and check if there is a match, ie. "it is for me" */
    while(if_walker)
    {
      /*if the destination ip address is the same as if_walker's ip*/
      if(ip_hdr->ip_dst == if_walker->ip)
      {
        /*if the packet is UDP or TCP*/
        if(ip_hdr->ip_p != ip_protocol_icmp)
        {
          /*call handle ICMP method for ICMP port unreachable*/
          handle_ICMP(sr, packet, if_walker, ICMP_type_port);
          return;

        }
        /*if the packet is ICMP*/
        else
        {
          sr_icmp_t11_hdr_t* icmp_hdr = (sr_icmp_t11_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
          /*call handle ICMP reply method if the ICMP type is echo, type 8*/
          if(icmp_hdr->icmp_type == 0x08)
          {
              handle_ICMP_reply(sr, packet, len, if_walker);
              return;
          }
        }
      }
      if_walker = if_walker->next;

    }

    /*if there is no match in the interface list, ie packet is not for ME
     *check the time to live field, if time to live is less than or equal to 1, send ICMP time exceeded
     */
    if(ip_hdr->ip_ttl <= 1)
    {
      /*call handle ICMP time exceeded method*/
      handle_ICMP(sr, packet, iface, ICMP_type_time);
      return;
    }
    /*decrement ttl field*/
    ip_hdr->ip_ttl--;
    /*call handle ip forwarding method to forward packet*/
    handle_IP_forwarding(sr, packet, len, iface);
}


/*---------------------------------------------------------------------
 * Method: sr_if* Longest_prefix_match
 * Scope:  Global
 *
 * This method is used to find out which the longest ip match in a router's
 * routing table 
 *---------------------------------------------------------------------*/
struct sr_if* Longest_prefix_match(struct sr_instance* sr, uint8_t * packet, uint32_t dest_ip)
{
  /*malloc the return sr instance */
  struct sr_if* LPM = NULL;

  /*get the routing table */
  struct sr_rt* rt_walker = sr->routing_table;
  /*loop through all entry in the routing table and find out the longest prefix match*/
  while(rt_walker)
  {
    uint32_t distance = rt_walker->mask.s_addr & dest_ip;
    /*if we find the longest match, we update the LPM interface*/
    if(distance == rt_walker->dest.s_addr & rt_walker->mask.s_addr)
    {
      LPM = malloc(sizeof(struct sr_if));
      LPM = sr_get_interface(sr, rt_walker->interface);
    }
    /*move the rt to next entry*/
    rt_walker = rt_walker->next;

  }
  return LPM;
}


/*---------------------------------------------------------------------
 * Method: handle_ICMP_reply
 * Scope:  Global
 *
 * This method is called each time the router receives an ICMP echo packet 
 * on the interface. 
 *---------------------------------------------------------------------*/
void handle_ICMP_reply(struct sr_instance* sr,
                 uint8_t * packet,
                 unsigned int len,
                 struct sr_if* current_Iface)
{
  /*get the ethernet header, ip header, icmp header*/
  sr_ethernet_hdr_t* e_hdr = (sr_ethernet_hdr_t*)packet;
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t));
  sr_icmp_t11_hdr_t* icmp_hdr = (sr_icmp_t11_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  /*find out which interface matched with out ip destination*/
  struct sr_if* LPM = Longest_prefix_match(sr, packet, ip_hdr->ip_src);
  /* null check the LPM */
  if(LPM == NULL)
  {
    fprintf(stderr, "should not be here\n");
    return;
  }

  /*change the ethernet destination to source and source to longest matching prefix interface's mac address*/
  memcpy(e_hdr->ether_dhost, e_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(e_hdr->ether_shost, LPM->addr, ETHER_ADDR_LEN);

  /*update ip' header, destination changed to source, source becomes current interface's ip addr*/
  ip_hdr->ip_dst = ip_hdr->ip_src;
  ip_hdr->ip_src = current_Iface->ip;
  /*calculate the checksum*/
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

  /*update icmp header field*/
  icmp_hdr->icmp_type = 0x00;
  icmp_hdr->icmp_code = 0x00;
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->icmp_sum = cksum(icmp_hdr, ntohs(len) - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

  /*send the packet*/
  sr_send_packet(sr, packet, len, LPM->name);

  /*free up the LPM we created*/
  /*free(LPM); */
}



/*---------------------------------------------------------------------
 * Method: handle_ICMP
 * Scope:  Global
 *
 * This method is called each time the router receives an UDP or TCP
 * packet or time exceeded or host unreachable, or net unreachable. 
 * Using switch case to figure out the ICMP type and code. 
 *---------------------------------------------------------------------*/
void handle_ICMP(struct sr_instance* sr,
                 uint8_t * packet,
                 struct sr_if* current_Iface,
                 uint8_t ICMP_type)
{
  /*create the ICMP type 3 packet*/
  uint8_t* ICMP_p = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t));

  /*get the TCP/UDP ethernet header and ip header*/
  sr_ethernet_hdr_t* e_hdr = (sr_ethernet_hdr_t*)packet;
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t));

  /*get the new ethernet, ip, and icmp header*/
  sr_ethernet_hdr_t* e_hdr_new = (sr_ethernet_hdr_t*)ICMP_p;
  sr_ip_hdr_t* ip_hdr_new = (sr_ip_hdr_t*)(ICMP_p+sizeof(sr_ethernet_hdr_t));
  sr_icmp_t11_hdr_t* icmp_hdr_new = (sr_icmp_t11_hdr_t*)(ICMP_p+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));

  /*find out which interface matched with out ip destination*/
  struct sr_if* LPM = Longest_prefix_match(sr, packet, ip_hdr->ip_src);
  /* null check the LPM */
  if(LPM == NULL)
  {
    return;
  }

  /*copy the ehter type field from previous to new ethernet header*/
  e_hdr_new->ether_type = e_hdr->ether_type;
  /*ether net header destination mac addr become previous ethernet header source mac addr*/
  memcpy(e_hdr_new->ether_dhost, e_hdr->ether_shost, ETHER_ADDR_LEN);
  /*ehternet source mac addr becomes our LPM's mac addr*/
  memcpy(e_hdr_new->ether_shost, LPM->addr, ETHER_ADDR_LEN);

  /*update ip header field
   *most of the field stay the same as previous ip header
   */
  ip_hdr_new->ip_tos = ip_hdr->ip_tos;
  /*new to review the len of ip header*/
  ip_hdr_new->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t));
  ip_hdr_new->ip_id = ip_hdr->ip_id;
  ip_hdr_new->ip_off = ip_hdr->ip_off;
  ip_hdr_new->ip_hl = ip_hdr->ip_hl;
  ip_hdr_new->ip_v = ip_hdr->ip_v;


  /*only change ttl, src, dst, and check sum, and ip protocol */
  ip_hdr_new->ip_p = ip_protocol_icmp;
  ip_hdr_new->ip_ttl = INIT_TTL;
  ip_hdr_new->ip_dst = ip_hdr->ip_src;
  ip_hdr_new->ip_src = current_Iface->ip;
  ip_hdr_new->ip_sum = 0;
  ip_hdr_new->ip_sum = cksum(ip_hdr_new, sizeof(sr_ip_hdr_t));


  /*update icmp header field*/
  switch(ICMP_type)
  {
    case ICMP_type_port:
      icmp_hdr_new->icmp_type = 0x03;
      icmp_hdr_new->icmp_code = 0x03;
      break;
    case ICMP_type_time:
      icmp_hdr_new->icmp_type = 0x0b;
      icmp_hdr_new->icmp_code = 0x00;
      break;
    case ICMP_type_host:
      icmp_hdr_new->icmp_type = 0x03;
      icmp_hdr_new->icmp_code = 0x01;
      break;
    case ICMP_type_net:
      icmp_hdr_new->icmp_type = 0x03;
      icmp_hdr_new->icmp_code = 0x00;
      break;
  }

  /* update the icmp data field, first 20 is ip header, and next 8 is datagram */
  memcpy(icmp_hdr_new->data, ip_hdr, ICMP_DATA_SIZE - 8);
  memcpy(icmp_hdr_new->data + 20, packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), 8);

  /*recompute the check sum*/
  icmp_hdr_new->icmp_sum = 0;
  icmp_hdr_new->icmp_sum = cksum(icmp_hdr_new, sizeof(sr_icmp_t11_hdr_t));

  /*send out the packet*/
  sr_send_packet(sr, ICMP_p, 
                 sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t11_hdr_t), 
                 LPM->name);
  /*free(LPM);*/
}

/*---------------------------------------------------------------------
 * Method: handle_ICMP_reply
 * Scope:  Global
 *
 * This method is called each time the router receives an IP packet that
 * is not for that router. 
 *---------------------------------------------------------------------*/
void handle_IP_forwarding(struct sr_instance* sr,
                 uint8_t * packet,
                 unsigned int len,
                 struct sr_if* current_Iface)
{
  fprintf(stderr, "just go into ip forwarding\n");
  /* get the ethernet and ip header */
  sr_ethernet_hdr_t* e_hdr = (sr_ethernet_hdr_t*)packet;
  sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t));

  /* get the LPM interface */
  struct sr_if* LPM = Longest_prefix_match(sr, packet, ip_hdr->ip_dst);

  /* there is no match in the routing table, send ICMP net unreachable */
  if(LPM == NULL)
  {
    handle_ICMP(sr, packet, current_Iface, ICMP_type_net);
  }

  /* if there is a match in the routing table, then forward the packet to 
   * the next hop router 
   */
  else
  {
    /* check if we get a cache hit for ARP */
    struct sr_arpentry * entry = sr_arpcache_lookup(&sr->cache, ip_hdr->ip_dst);
    /*if there is no match MAC in ARP cache, then we need to send out ARP request
     * for that next hop MAC addr 
     */
    if(entry == NULL)
    {
      /* we need to put the packet on the queue */
      struct sr_arpreq* arpreq = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, packet, len, LPM->name);
      /* call handle arp request method */
      handle_arpreq(sr, arpreq);
      return;
    }
    /* there is a match MAC in ARP cache, then we simply change the ethernet header
     * source and destination MAC addr and send out the packet to next hop 
     */
    else
    {
      /* the ethernet host mac is the current interface mac addr
       * the ethernet destination mac is the entry's mac addr 
       */
      memcpy(e_hdr->ether_shost, LPM->addr, ETHER_ADDR_LEN);
      memcpy(e_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);

      /* since we had decrement the ttl in handle IP, we have to recompute the check sum */
      ip_hdr->ip_sum = 0;
      ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

      /* forward the packet to the next hop */
      sr_send_packet(sr, packet, len, LPM->name);
      free(entry);
      return;
    }
  }
}






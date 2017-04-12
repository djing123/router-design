/* Name: Dadong Jing
 * PID: A99018211
 * Login: cs123wal
 */

 CSE 123 Proj 2 README

 In this project, I have modified two files. 
 In sr_router, I have implemented sr_handlepacket, sr_handleARP, sr_handlIP, Longest_prefix_match, handle_ICMP_reply, handle_ICMP, and handle_IP_forwarding.
 	In sr_handlepacket, I first check if it is a ARP packet and IP packet, and also check if the packet's length is appropriate. Then, I will
 	call handleARP or handleIP based on the packet type. 

 	In sr_handleARP, it has two part. First handle arp request packet, and second handle arp reply packet. In arp request, I switch the ethernet header's 
 	source and destination field. And for arp header, I change the type to arp reply, and change the arp header's ip source and target field. 

 	In sr_handlIP, I field check if the checksum is correct. Then I check if the ip version is ipv4. Then, we will loop through all interface and see if
 	there is a match in ip. If there is a match, then it means the packet is for me. Then, we need to check if the packet is a UPD/TCP or a ICMP echo request.
 	If it is a UDP/TCP, we will call handleICMP with type port unreachable, since router should not handle those packets. If it is a ICMP echo requset, I will
 	call handleICMP reply method. If we find out the packet is not for me, I will first check the ttl, and see if it reaches 1. If ttl is less than or equal to
 	1, i will call handleicmp method with type time exceeeded. If ttl is greater than 1, i will decrement the ttl by 1 and call ip forward method. 

 	In Longest_prefix_match, it will take in a ip address, and it will loop through that interface's entire routing table, and find out the longest prefix match
 	to return. If it finds nothing, return null.

 	In handle_ICMP_reply, I switch the ethernet header's source and destination filed. And update the ICMP header field. 

 	In handle_ICMP, I use Longest_prefix_match method to find out which interface it should be sent out in order to get the ethernet header destination mac addr
 	field. Then, I update the ICMP header based on the type passed into this method. (ie. ICMP type and code) Then, I will compute the check sum and send out the
 	ICMP packet. 

 	In handle_IP_forwarding, I first use Longest_prefix_match method to find out if there is a match in this interface's routing table. If there is not, I wil 	
 	send out a ICMP net unreachable using handle_ICMP. If i find a match, then I will check if there is a arp cache hit. If we already have the target mac addr,
 	then, i just update the ehternet header source and destination mac addr and recompute the check sum for ip header, and forward the packet. If there is a 
 	cache miss, then I will first queue the packet,and call handlearp to send out a arp request. 

 In sr_arpcache, I have implement sr_arpcache_sweepreqs and handle_arpreq.
 	In handle_arpreq, I basiclly follow the discussion slide sudo code. It first check if the time difference between last arp sent time and current time, if 
 	the difference is greater than 1, I will check how many arp request for that host I have sent previously. If more than 5 times, i will send out a ICMP host
 	unreachable. If less than 5 times, i will generate a arp request packet and send out that arp request. 

 	In sr_arpcache_sweepreqs, this method will constantly calling handle arp requst and check if we need to resend the arp or destory that request. 
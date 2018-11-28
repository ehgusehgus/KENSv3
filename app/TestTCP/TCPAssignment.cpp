/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"
#include <list>
using namespace std;
uint16_t PORTNUM = 0xcd11;
#define SEC  1000000000

namespace E
{

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{

}

void TCPAssignment::finalize()
{

}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET:
		this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case CLOSE:
		this->syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ:
		this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		this->syscall_connect(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		this->syscall_accept(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		this->syscall_getsockname(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		this->syscall_getpeername(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

//param1 = domain(AF_INIT) param2 = type param3 = protocol
void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int param1_int, int param2_int)
{
	int fd = createFileDescriptor(pid);
	if(fd != -1){
		struct Sock_element se;
		se.pid = pid;
		se.fd = fd;
		se.state = ST_CLOSED;
		se.uuid = syscallUUID;
		se.ser_addr = 0;
		se.ser_port = 0;
		se.seq = 0;
		Sock_list.push_front(se);
	}
	returnSystemCall(syscallUUID, fd);
}

//param1_int = fd;
void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int param1_int){

	list<Bind_element>::iterator iter;
	list<Sock_element>::iterator iter2;

	int b = 0;

	for(iter2 = Sock_list.begin(); iter2 != Sock_list.end();iter2++){
		if(iter2->pid == pid && iter2->fd == param1_int){
			b = 1;
			break;
		}
	}	

	if(b == 0){
		returnSystemCall(syscallUUID,-1);
	}

	b=0;
	for(iter = Bind_list.begin(); iter != Bind_list.end();iter++){
		if(iter->pid == pid && iter->fd == param1_int){
			b=1;
			break;
		}
	}
	if(b == 0){
		Sock_list.erase(iter2);
		returnSystemCall(syscallUUID,-1);
	}

	if(iter2->state<4){
		Sock_list.erase(iter2);
		Bind_list.erase(iter);		
	}
	else if(iter2->state == ST_ESTABLISHED){

		iter2->state = ST_FIN_WAIT1;
		Packet * newpacket = allocatePacket(sizeof(struct packet));
		struct packet_header head;
		head.pac_iphdr.saddr = iter2->cli_addr;
		head.pac_iphdr.daddr = iter2->ser_addr;
		head.pac_tcphdr.source = iter2->cli_port;
		head.pac_tcphdr.dest = iter2->ser_port;
		head.pac_tcphdr.seq = iter2->seq;
		head.pac_tcphdr.doff = sizeof(struct tcphdr) >> 2;
		head.pac_tcphdr.ack_seq = 0;
		head.pac_tcphdr.res1 = 0;
		head.pac_tcphdr.res2=0;
		head.pac_tcphdr.fin = 1;
		head.pac_tcphdr.syn = 0;
		head.pac_tcphdr.rst = 0;
		head.pac_tcphdr.psh = 0;
		head.pac_tcphdr.ack = 0;
		head.pac_tcphdr.urg = 0;
		head.pac_tcphdr.window = htons(51200);
		head.pac_tcphdr.check = 0;
		head.pac_tcphdr.check = htons(~NetworkUtil::tcp_sum(iter2->cli_addr, iter2->ser_addr, (uint8_t *)&head.pac_tcphdr, 20));
		iter2->seq = htonl(ntohl(iter2->seq)+1);

		newpacket->writeData(0, &head, sizeof(struct packet_header));

		struct Sock_element * a= (struct Sock_element *)malloc(sizeof(struct Sock_element));
		a->pid = iter2->pid;
		a->fd = iter2->fd;
		a->state = ST_CLOSE_WAIT;
		a->unordered = newpacket;
		addTimer((void *)a, (Time)SEC *5);



		//this->sendPacket("IPv4",newpacket);

	}
	else if(iter2->state == ST_CLOSE_WAIT){
		iter2->state = ST_LAST_ACK;
		Packet * newpacket = allocatePacket(sizeof(struct packet));
		struct packet_header head;
		head.pac_iphdr.saddr = iter2->cli_addr;
		head.pac_iphdr.daddr = iter2->ser_addr;
		head.pac_tcphdr.source = iter2->cli_port;
		head.pac_tcphdr.dest = iter2->ser_port;
		head.pac_tcphdr.seq = iter2->seq;
		head.pac_tcphdr.doff = sizeof(struct tcphdr) >> 2;
		head.pac_tcphdr.ack_seq = 0;
		head.pac_tcphdr.res1 = 0;
		head.pac_tcphdr.res2=0;
		head.pac_tcphdr.fin = 1;
		head.pac_tcphdr.syn = 0;
		head.pac_tcphdr.rst = 0;
		head.pac_tcphdr.psh = 0;
		head.pac_tcphdr.ack = 0;
		head.pac_tcphdr.urg = 0;
		head.pac_tcphdr.window = htons(51200);
		head.pac_tcphdr.check = 0;
		head.pac_tcphdr.check = htons(~NetworkUtil::tcp_sum(iter2->cli_addr, iter2->ser_addr, (uint8_t *)&head.pac_tcphdr, 20));
		iter2->seq = htonl(ntohl(iter2->seq)+1);
		newpacket->writeData(0, &head, sizeof(struct packet_header));

		this->sendPacket("IPv4",newpacket);
	}
	//removeFileDescriptor(pid, param1_int);
	//something!!
	//returnSystemCall(syscallUUID,0);

}

//param1 = fd, param2 = addr, param3 = addrlen
void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int param1_int, struct sockaddr * param2_ptr, socklen_t param3_int )
{
	list<Bind_element>::iterator iter;
	list<Sock_element>::iterator iter2;

	int b=0;

	for(iter2 = Sock_list.begin(); iter2 != Sock_list.end();iter2++){
		if(iter2->pid == pid && iter2->fd == param1_int){
			b = 1;
			break;
		}
	}		
	if(b == 0){
		returnSystemCall(syscallUUID,-1);
	}

	struct Bind_element be;
	be.pid = pid;
	be.fd = param1_int;
	be.addr = ((struct sockaddr_in *) param2_ptr)->sin_addr.s_addr;
	be.port = ((struct sockaddr_in *) param2_ptr)->sin_port;
	be.family = ((struct sockaddr_in *) param2_ptr)->sin_family;
	be.len = param3_int;

	for(iter = Bind_list.begin(); iter != Bind_list.end();iter++){
		if(iter->pid == pid && iter->fd == be.fd){
			returnSystemCall(syscallUUID, -1);
		}

		if(iter->port == be.port && (iter->addr == be.addr || iter->addr == INADDR_ANY || be.addr == INADDR_ANY)){
			returnSystemCall(syscallUUID, -1);
		}
	}
	Bind_list.push_front(be);
	returnSystemCall(syscallUUID, 0);
}
//param1 = fd, param2 = addr, param3 = addrlen
void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int param1_int, struct sockaddr * param2_ptr, socklen_t * param3_int )
{
	list<Bind_element>::iterator iter;
	list<Sock_element>::iterator iter2;

	for(iter2 = Sock_list.begin(); iter2 != Sock_list.end();iter2++){
		if((iter2->pid == pid && iter2->fd ==param1_int) && iter2->cli_port != 0 ){
			((struct sockaddr_in *)param2_ptr)->sin_family = AF_INET;
			((struct sockaddr_in *)param2_ptr)->sin_port = iter2->cli_port;
			((struct sockaddr_in *)param2_ptr)->sin_addr.s_addr = iter2->cli_addr;
			*(param3_int) = sizeof(struct sockaddr);
			returnSystemCall(syscallUUID, 0);
			return;
		}	
	}

	for(iter = Bind_list.begin(); iter != Bind_list.end();iter++){
		if(iter->pid == pid && iter->fd ==param1_int){
			((struct sockaddr_in *)param2_ptr)->sin_family = iter->family;
			((struct sockaddr_in *)param2_ptr)->sin_port = iter->port;
			((struct sockaddr_in *)param2_ptr)->sin_addr.s_addr = iter->addr;
			*(param3_int) = iter->len;
			returnSystemCall(syscallUUID, 0);
		}	
	}
	returnSystemCall(syscallUUID, -1);
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int fd, struct sockaddr* addr, socklen_t len){

	list<Bind_element>::iterator iter;
	list<Sock_element>::iterator iter2;

	int b = 0;
	for(iter2 = Sock_list.begin(); iter2 != Sock_list.end();iter2++){
		if(iter2->pid == pid && iter2->fd == fd){
			b = 1;
			break;
		}
	}	

	if(b == 0){
		returnSystemCall(syscallUUID,-1);
	}

	b= 0;
	for(iter = Bind_list.begin(); iter != Bind_list.end();iter++){
		if(iter->pid == pid && iter->fd == fd){
			b=1;
			break;
		}
	}

	struct Bind_element be;
	if(b == 0){
		int port = getHost()->getRoutingTable((uint8_t *) &((struct sockaddr_in *) addr)->sin_addr.s_addr);
		getHost()->getIPAddr((uint8_t *)&be.addr,port);
		be.pid = pid;
		be.fd = fd;
		be.port = PORTNUM;
		PORTNUM++;

		be.family = AF_INET;
		be.len = sizeof(struct sockaddr);
		Bind_list.push_front(be);

	}
	else{
		be.addr = iter->addr;
		be.port = iter->port;
	}
	iter2->state = ST_SYN_SENT;
	iter2->ser_addr = ((struct sockaddr_in *) addr)->sin_addr.s_addr;
	iter2->ser_port = ((struct sockaddr_in *) addr)->sin_port;
	iter2->uuid = syscallUUID;

	Packet * newpacket = allocatePacket(sizeof(struct packet));
	struct packet_header head;
	head.pac_iphdr.saddr = be.addr;
	head.pac_iphdr.daddr = iter2->ser_addr;
	head.pac_tcphdr.source = be.port;
	head.pac_tcphdr.dest = iter2->ser_port;
	head.pac_tcphdr.seq = iter2->seq;
	head.pac_tcphdr.doff = sizeof(struct tcphdr) >> 2;
	head.pac_tcphdr.res1 = 0;
	head.pac_tcphdr.res2=0;
	head.pac_tcphdr.fin = 0;
	head.pac_tcphdr.syn = 1;
	head.pac_tcphdr.rst = 0;
	head.pac_tcphdr.psh = 0;
	head.pac_tcphdr.ack = 0;
	head.pac_tcphdr.urg = 0;
	head.pac_tcphdr.ack_seq = 0;
	head.pac_tcphdr.window = htons(51200);
	head.pac_tcphdr.check = 0;
	head.pac_tcphdr.check = htons(~NetworkUtil::tcp_sum(be.addr, iter2->ser_addr, (uint8_t *)&head.pac_tcphdr, 20));
	newpacket->writeData(0, &head, sizeof(struct packet_header));
	iter2->seq = htonl(ntohl(iter2->seq)+1);

	Packet * storing = this->clonePacket(newpacket);

	this->sendPacket("IPv4",newpacket);

	struct Sock_element * a= (struct Sock_element *)malloc(sizeof(struct Sock_element));
	a->pid = iter2->pid;
	a->fd = iter2->fd;
	a->state = ST_SYN_SENT;
	a->unordered = storing;
	addTimer((void *)a, (Time)SEC/10);

}
void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int fd, int backlog){

	list<Bind_element>::iterator iter;
	list<Sock_element>::iterator iter2;

	int b = 0;
	for(iter2 = Sock_list.begin(); iter2 != Sock_list.end();iter2++){
		if(iter2->pid == pid && iter2->fd == fd){
			b = 1;
			break;
		}
	}	

	if(b == 0){
		returnSystemCall(syscallUUID,-1);
	}

	b= 0;
	for(iter = Bind_list.begin(); iter != Bind_list.end();iter++){
		if(iter->pid == pid && iter->fd == fd){
			b=1;
			break;
		}
	}
	if(b == 0){
		returnSystemCall(syscallUUID,-1);
	}

	iter2->state = ST_LISTEN;
	iter2->backlog = backlog;

	returnSystemCall(syscallUUID,0);

}
void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int fd, struct sockaddr* addr, socklen_t * len){

	if(Completed_list.empty()){
		struct Accept_element ae;
		ae.pid =pid;
		ae.fd= fd;
		ae.uuid = syscallUUID;
		ae.addr = addr;
		ae.len = len;
		acceptwait.push_back(ae);
	}
	else{
		struct Completed_element completed = Completed_list.front();

		((struct sockaddr_in *) addr)->sin_family = AF_INET;
		((struct sockaddr_in *) addr)->sin_port = completed.cli_port;
		((struct sockaddr_in *) addr)->sin_addr.s_addr = completed.cli_addr;

		*len = sizeof(struct sockaddr);

		int newsock = createFileDescriptor(pid);
		struct Sock_element se;
		se.pid = pid;
		se.fd = newsock;
		se.state = ST_ESTABLISHED;
		se.uuid = syscallUUID;
		se.cli_addr = completed.ser_addr;
		se.cli_port = completed.ser_port;
		se.ser_addr = completed.cli_addr;
		se.ser_port = completed.cli_port;
		se.ack_seq = completed.ack_seq;
		se.backlog = 0;
		se.seq = htonl(1);
		Sock_list.push_front(se);

		struct Bind_element be;
		be.pid = pid;
		be.fd = newsock;
		be.addr = completed.cli_addr;
		be.port = completed.cli_port;
		be.family = AF_INET;
		be.len = sizeof(struct sockaddr);
		Bind_list.push_front(be);

		Completed_list.pop_front();
		returnSystemCall(syscallUUID, newsock);

	}

}
void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int fd, struct sockaddr* addr, socklen_t * len){

	list<Sock_element>::iterator iter;

	int b = 0;
	for(iter = Sock_list.begin(); iter != Sock_list.end();iter++){
		if(iter->pid == pid && iter->fd == fd){
			b = 1;
			break;
		}
	}	

	if(b == 0){
		returnSystemCall(syscallUUID,-1);
	}
	if(iter->ser_port == 0){
		returnSystemCall(syscallUUID, -1);
	}

	((struct sockaddr_in *) addr)->sin_family = AF_INET;
	((struct sockaddr_in *) addr)->sin_port = iter->ser_port;
	((struct sockaddr_in *) addr)->sin_addr.s_addr = iter->ser_addr;
	*len = sizeof(struct sockaddr);
	returnSystemCall(syscallUUID,0);

}

void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int fd, void* buf, int size){
	list<Bind_element>::iterator iter;
	list<Sock_element>::iterator iter2;

	int b = 0;
	for(iter2 = Sock_list.begin(); iter2 != Sock_list.end();iter2++){
		if(iter2->pid == pid && iter2->fd == fd){
			b = 1;
			break;
		}
	}	

	if(b == 0){
		returnSystemCall(syscallUUID,-1);
	}

	b= 0;
	for(iter = Bind_list.begin(); iter != Bind_list.end();iter++){
		if(iter->pid == pid && iter->fd == fd){
			b=1;
			break;
		}
	}

	if(b == 0){
		returnSystemCall(syscallUUID,-1);
	}

	// if(size ==0){
	// 	returnSystemCall(syscallUUID, 0);
	// } 
	if(iter2->last_byte_read == iter2->last_byte_rcvd){
		iter2->uuid =syscallUUID;
		iter2->read_size = size;
		iter2->read_buf = (char *)buf;
		return;
	}
	//printf("%d\n", size);
	int read_count = 0;

	// printf("%d %d %d %d %d\n",size, iter2->read_offset, iter2->received_packet_list.size(), iter2->fd, iter2->pid);
	while(iter2->received_packet_list.size() > 0 && read_count < size){
		Packet * read_packet = iter2->received_packet_list.front();

		//printf("ang? %d %d %d\n",  size-read_count, read_packet->getSize()-54-iter2->read_offset, iter2->read_offset);

		if(read_packet->getSize()-54-iter2->read_offset> size-read_count){
			read_packet->readData(54+iter2->read_offset, (char *)buf+read_count, size-read_count);
			iter2->read_offset +=(size-read_count);
			read_count += (size-read_count);
			break;
		}
		else{
			read_packet->readData(54+iter2->read_offset, (char *)buf+read_count, read_packet->getSize()-54- iter2->read_offset);
			read_count += (read_packet->getSize() - 54 - iter2->read_offset);
			iter2->received_packet_list.pop_front();
			freePacket(read_packet);
			iter2->read_offset = 0;
		}

	}
	iter2->last_byte_read += read_count;
	//printf("%d %d %d\n", iter2->last_byte_read, iter2->last_byte_rcvd, iter2->received_packet_list.size());
	returnSystemCall(syscallUUID, read_count);

}

void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int fd, void* buf, int size){

	list<Bind_element>::iterator iter;
	list<Sock_element>::iterator iter2;

	int b = 0;
	for(iter2 = Sock_list.begin(); iter2 != Sock_list.end();iter2++){
		if(iter2->pid == pid && iter2->fd == fd){
			b = 1;
			break;
		}
	}	

	if(b == 0){
		returnSystemCall(syscallUUID,-1);
	}

	b= 0;
	for(iter = Bind_list.begin(); iter != Bind_list.end();iter++){
		if(iter->pid == pid && iter->fd == fd){
			b=1;
			break;
		}
	}

	if(b == 0){
		returnSystemCall(syscallUUID,-1);
	}

	if(iter2->state != ST_ESTABLISHED){
		returnSystemCall(syscallUUID, -1);
	}


	int sent_count = 0;
	iter2->uuid = syscallUUID;
	while(size > 0){
		int current_send =0;
		if(size>=512){
			current_send = 512;
			size -= 512;
		}
		else{
			current_send = size;
			size = 0;
		}

		// if(iter2->last_byte_sent - iter2->last_byte_acked >= iter2->cwnd){
			
		// 	iter2->last_byte_sent+=current_send;
		// 	+

		// } 
		// else{

		// }

		Packet * newpacket = allocatePacket(sizeof(struct packet)+current_send);
		
		uint8_t inter_packet[current_send+20];

		struct packet_header head;
		head.pac_iphdr.saddr = iter2->cli_addr;
		head.pac_iphdr.daddr = iter2->ser_addr;
		head.pac_tcphdr.source = iter2->cli_port;
		head.pac_tcphdr.dest = iter2->ser_port;
		head.pac_tcphdr.seq = iter2->seq;
		head.pac_tcphdr.doff = sizeof(struct tcphdr) >> 2;
		head.pac_tcphdr.res1 = 0;
		head.pac_tcphdr.res2 = 0;
		head.pac_tcphdr.fin = 0;
		head.pac_tcphdr.syn = 0;
		head.pac_tcphdr.rst = 0;
		head.pac_tcphdr.psh = 0;
		head.pac_tcphdr.ack = 1;
		head.pac_tcphdr.urg = 0;
		head.pac_tcphdr.ack_seq = iter2->ack_seq;
		head.pac_tcphdr.window = htons(51200);
		head.pac_tcphdr.check = 0;
		memcpy(inter_packet, &head.pac_tcphdr, 20);
		memcpy(inter_packet+20, (char *)buf+sent_count, current_send);
		head.pac_tcphdr.check = htons(~NetworkUtil::tcp_sum(iter2->cli_addr, iter2->ser_addr, inter_packet, 20+current_send));
		
		newpacket->writeData(0, &head, sizeof(struct packet_header));
		newpacket->writeData(54,(char *)buf+sent_count,current_send);
		iter2->seq = htonl(ntohl(iter2->seq)+current_send);

		Packet *storing = this->clonePacket(newpacket);


		this->sendPacket("IPv4",newpacket);


		iter2->sent_packet_list.push_back(storing);
		sent_count += current_send;

		if(iter2->timerID ==0){
			//Time currentTime = this->getHost()->getSystem()->getCurrentTime();
			//currentTime = currentTime + ((Time) SEC/10);
			struct Sock_element * a= (struct Sock_element *)malloc(sizeof(struct Sock_element));
			a->pid = iter2->pid;
			a->fd = iter2->fd;
			a->state = ST_ESTABLISHED;
			iter2->timerID = addTimer(a, (Time) SEC/100);
		}

	}

	returnSystemCall(syscallUUID, sent_count);
}


void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
		// Count++;
		// int b2;
		// uint8_t * received2 = (uint8_t *)malloc(54);
		// packet->readData(0,received2,54);

		// if(Count<10){
		// 	for(b2=0;b2<54; b2++){
		// 		printf("%x ", *((uint8_t *)received2+b2));
		// 	}
		// printf("\n");
		// }
		// free(received2);




	list<Bind_element>::iterator iter;
	list<Sock_element>::iterator iter2;

	int b=0;

	struct packet received;

	packet->readData(0, &received, sizeof(struct packet));


	uint8_t inter_packet[packet->getSize()-54+20];
	packet->readData(34, inter_packet, sizeof(inter_packet));

	uint16_t checksum = ~NetworkUtil::tcp_sum(received.packet_header.pac_iphdr.saddr, received.packet_header.pac_iphdr.daddr,inter_packet, 20+packet->getSize()-54);
	
	//printf("%x %d %d\n", checksum, received.packet_header.pac_tcphdr.ack, received.packet_header.pac_tcphdr.syn);
	
	
	if (checksum != 0)
	{
		this->freePacket(packet);
		return;
	}

	//SYNACK

	if(received.packet_header.pac_tcphdr.syn ==1 && received.packet_header.pac_tcphdr.ack ==1){

		uint32_t received_daddr = received.packet_header.pac_iphdr.daddr;
		uint32_t received_dport = received.packet_header.pac_tcphdr.dest;
		uint32_t received_saddr = received.packet_header.pac_iphdr.saddr;
		uint32_t received_sport = received.packet_header.pac_tcphdr.source;

		b=0;
		for(iter = Bind_list.begin(); iter != Bind_list.end();iter++){
			if(iter->addr == received_saddr && iter->port == received_sport){
				b=1;
				break;
			}
		}

		if(b == 0){
			for(iter = Bind_list.begin(); iter != Bind_list.end();iter++){
				// printf("%x!!!!\n", iter->addr);
				// printf("%x???\n", iter->port);
				// printf("%x***\n", received_daddr);
				// printf("%x^^^\n", received_dport);
				if((iter->addr == received_daddr || iter->addr == INADDR_ANY) && iter->port == received_dport){
					b=1;
					break;
				}
			}
			if(b == 0){
				freePacket(packet);
				return;
			}
		}


		b=0;
		for(iter2 = Sock_list.begin(); iter2 != Sock_list.end();iter2++){
			if(iter2->pid == iter->pid && iter2->fd == iter->fd){
				b = 1;
				break;
			}
		}	
		if(b == 0){
			freePacket(packet);
			return;
		}


		if(iter2->state == ST_SYN_SENT){
			if(iter2->seq != received.packet_header.pac_tcphdr.ack_seq){
				freePacket(packet);
				return;
			}
			Packet * newpacket = allocatePacket(sizeof(struct packet));
			struct packet_header head;
			head.pac_iphdr.saddr = received_daddr;
			head.pac_iphdr.daddr = received_saddr;
			head.pac_tcphdr.source = received_dport;
			head.pac_tcphdr.dest = received_sport;
			head.pac_tcphdr.seq = iter2->seq;
			head.pac_tcphdr.doff = sizeof(struct tcphdr) >> 2;
			head.pac_tcphdr.ack_seq = htonl(ntohl(received.packet_header.pac_tcphdr.seq)+1);
			head.pac_tcphdr.fin = 0;
			head.pac_tcphdr.syn = 0;
			head.pac_tcphdr.rst = 0;
			head.pac_tcphdr.psh = 0;
			head.pac_tcphdr.ack = 1;
			head.pac_tcphdr.urg = 0;
			head.pac_tcphdr.window = received.packet_header.pac_tcphdr.window;
			head.pac_tcphdr.check = 0;
			head.pac_tcphdr.check = htons(~NetworkUtil::tcp_sum(received_daddr, received_saddr, (uint8_t *)&head.pac_tcphdr, 20));
			newpacket->writeData(0, &head, sizeof(struct packet_header));
			
			// Pakcet * storing = this->clonePacket(newpacket);
			this->sendPacket("IPv4",newpacket);
			this->freePacket(packet);

			iter2->state = ST_ESTABLISHED;
			iter2->ack_seq = htonl(ntohl(received.packet_header.pac_tcphdr.seq)+1);
			iter2->cli_addr = received_daddr;
			iter2->cli_port = received_dport;
			iter2->ser_addr = received_saddr;
			iter2->ser_port = received_sport;

			// struct Sock_element * a= (struct Sock_element *)malloc(sizeof(struct Sock_element));
			// a->pid = iter2->pid;
			// a->fd = iter2->fd;
			// a->state = ST_SYN_RCVD;
			// a->unordered = storing;
			// addTimer((void *)a, (Time)SEC/10);
			returnSystemCall(iter2->uuid, 0);

		}
		else{

			Packet * newpacket = allocatePacket(sizeof(struct packet));
			struct packet_header head;
			head.pac_iphdr.saddr = received_daddr;
			head.pac_iphdr.daddr = received_saddr;
			head.pac_tcphdr.source = received_dport;
			head.pac_tcphdr.dest = received_sport;
			head.pac_tcphdr.seq = iter2->seq;
			head.pac_tcphdr.doff = sizeof(struct tcphdr) >> 2;
			head.pac_tcphdr.ack_seq = htonl(ntohl(received.packet_header.pac_tcphdr.seq)+1);
			head.pac_tcphdr.fin = 0;
			head.pac_tcphdr.syn = 0;
			head.pac_tcphdr.rst = 0;
			head.pac_tcphdr.psh = 0;
			head.pac_tcphdr.ack = 1;
			head.pac_tcphdr.urg = 0;
			head.pac_tcphdr.window = received.packet_header.pac_tcphdr.window;
			head.pac_tcphdr.check = 0;
			head.pac_tcphdr.check = htons(~NetworkUtil::tcp_sum(received_daddr, received_saddr, (uint8_t *)&head.pac_tcphdr, 20));
			newpacket->writeData(0, &head, sizeof(struct packet_header));
			
			//iter2->ack_seq = ntohl(received.packet_header.pac_tcphdr.ack_seq);

			// Pakcet * storing = this->clonePacket(newpacket);
			this->sendPacket("IPv4",newpacket);
			this->freePacket(packet);

		}

	}//SYN
	else if(received.packet_header.pac_tcphdr.syn ==1){


		uint32_t received_daddr = received.packet_header.pac_iphdr.daddr;
		uint32_t received_dport = received.packet_header.pac_tcphdr.dest;
		uint32_t received_saddr = received.packet_header.pac_iphdr.saddr;
		uint32_t received_sport = received.packet_header.pac_tcphdr.source;

		b=0;
		for(iter = Bind_list.begin(); iter != Bind_list.end();iter++){
			if(iter->addr == received_saddr && iter->port == received_sport){
				b=1;
				break;
			}
		}

		if(b == 0){
			for(iter = Bind_list.begin(); iter != Bind_list.end();iter++){
				// printf("%x!!!!\n", iter->addr);
				// printf("%x???\n", iter->port);
				// printf("%x***\n", received_daddr);
				// printf("%x^^^\n", received_dport);
				if((iter->addr == received_daddr || iter->addr == INADDR_ANY) && iter->port == received_dport){
					b=1;
					break;
				}
			}
			if(b == 0){
				freePacket(packet);
				return;
			}
		}


		b=0;
		for(iter2 = Sock_list.begin(); iter2 != Sock_list.end();iter2++){
			if(iter2->pid == iter->pid && iter2->fd == iter->fd){
				b = 1;
				break;
			}
		}	
		if(b == 0){
			freePacket(packet);
			return;
		}




		if(iter2->state == ST_LISTEN){

			struct Pennding_element pe;
			pe.state = ST_SYN_RCVD;
			pe.addr = received_saddr;
			pe.port = received_sport;
			pe.seq = htonl(ntohl(received.packet_header.pac_tcphdr.seq)+1);

			list<Pennding_element>::iterator iter3;
			int b= 0;
			for(iter3 = iter2->pennding_list.begin(); iter3 != iter2->pennding_list.end();iter3++){
				if(iter3->addr == pe.addr && iter3->port == pe.port){
					b=1;
					return;
				}
			}

			if(b ==0){
				if(iter2->backlog > iter2->pennding_list.size())
					iter2->pennding_list.push_back(pe);
				else{
					freePacket(packet);
					return;
				}
			}
			Packet * newpacket = allocatePacket(sizeof(struct packet));
			struct packet_header head;
			head.pac_iphdr.saddr = received_daddr;
			head.pac_iphdr.daddr = received_saddr;
			head.pac_tcphdr.source = received_dport;
			head.pac_tcphdr.dest = received_sport;
			head.pac_tcphdr.seq = 0;
			head.pac_tcphdr.doff = sizeof(struct tcphdr) >> 2;
			head.pac_tcphdr.ack_seq = htonl(ntohl(received.packet_header.pac_tcphdr.seq)+1);
			head.pac_tcphdr.fin = 0;
			head.pac_tcphdr.syn = 1;
			head.pac_tcphdr.rst = 0;
			head.pac_tcphdr.psh = 0;
			head.pac_tcphdr.ack = 1;
			head.pac_tcphdr.urg = 0;
			head.pac_tcphdr.window = received.packet_header.pac_tcphdr.window;
			head.pac_tcphdr.check = 0;
			head.pac_tcphdr.check = htons(~NetworkUtil::tcp_sum(received_daddr, received_saddr, (uint8_t *)&head.pac_tcphdr, 20));

			newpacket->writeData(0, &head, sizeof(struct packet_header));

			Packet *storing = this->clonePacket(newpacket);


			this->sendPacket("IPv4",newpacket);
			this->freePacket(packet);
			iter2->sent_packet_list.push_back(storing);
			if(iter2->timerID ==0){
				//Time currentTime = this->getHost()->getSystem()->getCurrentTime();
				//currentTime = currentTime + ((Time) SEC/10);
				struct Sock_element * a= (struct Sock_element *)malloc(sizeof(struct Sock_element));
				a->pid = iter2->pid;
				a->fd = iter2->fd;
				a->state = ST_LISTEN;
				iter2->timerID = addTimer(a, (Time) SEC/10);
			}
			return;

		}

		if(iter2->state == ST_SYN_SENT){

			Packet * newpacket = allocatePacket(sizeof(struct packet));
			struct packet_header head;
			head.pac_iphdr.saddr = received_daddr;
			head.pac_iphdr.daddr = received_saddr;
			head.pac_tcphdr.source = received_dport;
			head.pac_tcphdr.dest = received_sport;
			head.pac_tcphdr.seq = 0;
			head.pac_tcphdr.doff = sizeof(struct tcphdr) >> 2;
			head.pac_tcphdr.ack_seq = htonl(ntohl(received.packet_header.pac_tcphdr.seq)+1);
			head.pac_tcphdr.fin = 0;
			head.pac_tcphdr.syn = 1;
			head.pac_tcphdr.rst = 0;
			head.pac_tcphdr.psh = 0;
			head.pac_tcphdr.ack = 1;
			head.pac_tcphdr.urg = 0;
			head.pac_tcphdr.window = received.packet_header.pac_tcphdr.window;
			head.pac_tcphdr.check = 0;
			head.pac_tcphdr.check = htons(~NetworkUtil::tcp_sum(received_daddr, received_saddr, (uint8_t *)&head.pac_tcphdr, 20));

			newpacket->writeData(0, &head, sizeof(struct packet_header));

			this->sendPacket("IPv4",newpacket);
			this->freePacket(packet);
		}


	}//ACK
	else if(received.packet_header.pac_tcphdr.ack ==1){

		uint32_t received_daddr = received.packet_header.pac_iphdr.daddr;
		uint32_t received_dport = received.packet_header.pac_tcphdr.dest;
		uint32_t received_saddr = received.packet_header.pac_iphdr.saddr;
		uint32_t received_sport = received.packet_header.pac_tcphdr.source;

		b=0;
		for(iter = Bind_list.begin(); iter != Bind_list.end();iter++){
			if(iter->addr == received_saddr && iter->port == received_sport){
				b=1;
				break;
			}
		}

		if(b == 0){
			list<Completed_element>::iterator iter3;
			for(iter3 = Completed_list.begin(); iter3 != Completed_list.end();iter3++){
				if(iter3->cli_addr == received_saddr && iter3->cli_port == received_sport){
					// Packet * newpacket = allocatePacket(sizeof(struct packet));
					// struct packet_header head;
					// head.pac_iphdr.saddr = received_daddr;
					// head.pac_iphdr.daddr = received_saddr;
					// head.pac_tcphdr.source = received_dport;
					// head.pac_tcphdr.dest = received_sport;
					// head.pac_tcphdr.seq = htonl(1);
					// head.pac_tcphdr.doff = sizeof(struct tcphdr) >> 2;
					// head.pac_tcphdr.ack_seq = htonl(ntohl(received.packet_header.pac_tcphdr.seq)+1);
					// head.pac_tcphdr.res1 = 0;
					// head.pac_tcphdr.res2= 0;
					// head.pac_tcphdr.fin = 0;
					// head.pac_tcphdr.syn = 0;
					// head.pac_tcphdr.rst = 0;
					// head.pac_tcphdr.psh = 0;
					// head.pac_tcphdr.ack = 1;
					// head.pac_tcphdr.urg = 0;
					// head.pac_tcphdr.window = received.packet_header.pac_tcphdr.window;
					// head.pac_tcphdr.check = 0;
					// head.pac_tcphdr.check = htons(~NetworkUtil::tcp_sum(received_daddr, received_saddr, (uint8_t *)&head.pac_tcphdr, 20));

					// newpacket->writeData(0, &head, sizeof(struct packet_header));

					// this->sendPacket("IPv4",newpacket);
					// this->freePacket(packet);
					
					//time_sleep;
					Completed_list.erase(iter3);

					return;
				}
			}
			for(iter = Bind_list.begin(); iter != Bind_list.end();iter++){
				// printf("%x!!!!\n", iter->addr);
				// printf("%x???\n", iter->port);
				// printf("%x***\n", received_daddr);
				// printf("%x^^^\n", received_dport);
				if((iter->addr == received_daddr || iter->addr == INADDR_ANY) && iter->port == received_dport){
					b=1;
					break;
				}
			}
			if(b == 0){
				freePacket(packet);
				return;
			}
		}


		b=0;
		for(iter2 = Sock_list.begin(); iter2 != Sock_list.end();iter2++){
			if(iter2->pid == iter->pid && iter2->fd == iter->fd){
				b = 1;
				break;
			}
		}	
		if(b == 0){
			freePacket(packet);
			return;
		}
//			printf("cccccccc2222222222        %d\n", iter2->state);

		if(iter2->state == ST_ESTABLISHED || iter2->state == ST_CLOSE_WAIT ||iter2->state ==ST_FIN_WAIT1){
				 // printf("%x %x\n", ntohl(received.packet_header.pac_tcphdr.seq),ntohl(iter2->ack_seq));

				// char str[4];
				// int i;
				// packet->readData(54, str, 4);

				// for(i=0; i<4;i++)
				// 	printf("%x\n",str[i]);



			if(iter2->sent_packet_list.size()>0){
				//if received data-client
				Packet * sent_packet = iter2->sent_packet_list.front();
				struct packet inter;
				sent_packet->readData(0, &inter, sizeof(struct packet));
				while(ntohl(inter.packet_header.pac_tcphdr.seq) < ntohl(received.packet_header.pac_tcphdr.ack_seq)){
					if(iter2->timerID !=0){
						cancelTimer(iter2->timerID);
						iter2->timerID = 0;
					}
					iter2->sent_packet_list.pop_front();
					freePacket(sent_packet);
					if(iter2->sent_packet_list.size()==0)
						break;
					sent_packet = iter2->sent_packet_list.front();
					sent_packet->readData(0, &inter, sizeof(struct packet));
				}
				iter2->last_byte_acked = received.packet_header.pac_tcphdr.ack_seq;
				this->freePacket(packet);
				if(iter2->timerID ==0 && iter2->sent_packet_list.size()>0){
					//Time currentTime = this->getHost()->getSystem()->getCurrentTime();
					//currentTime = currentTime + ((Time) SEC/10);
					struct Sock_element * a= (struct Sock_element *)malloc(sizeof(struct Sock_element));
					a->pid = iter2->pid;
					a->fd = iter2->fd;
					a->state = ST_ESTABLISHED;
					iter2->timerID = addTimer(a, (Time) SEC/10);
				}
				return;
			}

			if(packet->getSize() == 54){
				freePacket(packet);
				return;
			}
			if(ntohl(received.packet_header.pac_tcphdr.seq) > ntohl(iter2->ack_seq)){
				//printf("%x %x \n", ntohl(received.packet_header.pac_tcphdr.seq), ntohl(iter2->ack_seq));
				// printf("%x %x\n", ntohl(received.packet_header.pac_tcphdr.seq),ntohl(iter2->ack_seq));
				//printf("%x\n", iter2->ack_seq);
				Packet * newpacket = allocatePacket(sizeof(struct packet));
				struct packet_header head;
				head.pac_iphdr.saddr = received_daddr;
				head.pac_iphdr.daddr = received_saddr;
				head.pac_tcphdr.source = received_dport;
				head.pac_tcphdr.dest = received_sport;
				head.pac_tcphdr.seq = iter2->seq;
				head.pac_tcphdr.doff = sizeof(struct tcphdr) >> 2;
				head.pac_tcphdr.ack_seq = iter2->ack_seq;
				head.pac_tcphdr.res1 = 0;
				head.pac_tcphdr.res2= 0;
				head.pac_tcphdr.fin = 0;
				head.pac_tcphdr.syn = 0;
				head.pac_tcphdr.rst = 0;
				head.pac_tcphdr.psh = 0;
				head.pac_tcphdr.ack = 1;
				head.pac_tcphdr.urg = 0;
				head.pac_tcphdr.window = received.packet_header.pac_tcphdr.window;
				head.pac_tcphdr.check = 0;
				head.pac_tcphdr.check = htons(~NetworkUtil::tcp_sum(received_daddr, received_saddr, (uint8_t *)&head.pac_tcphdr, 20));

				newpacket->writeData(0, &head, sizeof(struct packet_header));

				iter2->unordered = packet; 

				this->sendPacket("IPv4",newpacket);
				//this->freePacket(packet);
				return;

				}

			if(ntohl(received.packet_header.pac_tcphdr.seq) < ntohl(iter2->ack_seq)){
				//printf("%x %x \n", ntohl(received.packet_header.pac_tcphdr.seq), ntohl(iter2->ack_seq));
//printf("cccccccc2\n");
				// printf("%x %x\n", ntohl(received.packet_header.pac_tcphdr.seq),ntohl(iter2->ack_seq));
				//printf("%x\n", iter2->ack_seq);
				Packet * newpacket = allocatePacket(sizeof(struct packet));
				struct packet_header head;
				head.pac_iphdr.saddr = received_daddr;
				head.pac_iphdr.daddr = received_saddr;
				head.pac_tcphdr.source = received_dport;
				head.pac_tcphdr.dest = received_sport;
				head.pac_tcphdr.seq = iter2->seq;
				head.pac_tcphdr.doff = sizeof(struct tcphdr) >> 2;
				head.pac_tcphdr.ack_seq = iter2->ack_seq;
				head.pac_tcphdr.res1 = 0;
				head.pac_tcphdr.res2= 0;
				head.pac_tcphdr.fin = 0;
				head.pac_tcphdr.syn = 0;
				head.pac_tcphdr.rst = 0;
				head.pac_tcphdr.psh = 0;
				head.pac_tcphdr.ack = 1;
				head.pac_tcphdr.urg = 0;
				head.pac_tcphdr.window = received.packet_header.pac_tcphdr.window;
				head.pac_tcphdr.check = 0;
				head.pac_tcphdr.check = htons(~NetworkUtil::tcp_sum(received_daddr, received_saddr, (uint8_t *)&head.pac_tcphdr, 20));

				newpacket->writeData(0, &head, sizeof(struct packet_header));

				this->sendPacket("IPv4",newpacket);
				//this->freePacket(packet);
				return;

				}

			// if(ntohl(iter2->ack_seq)>=ntohl(received.packet_header.pac_tcphdr.seq)+512){
			// 	printf("%x %x \n",ntohl(iter2->ack_seq), ntohl(received.packet_header.pac_tcphdr.seq)+512);
			// 	return;
			// }

			// if(iter2->ack_seq > received.packet_header.pac_tcphdr.seq) {
			// 	return;
			// }

			if(iter2->read_size >0){

				if(iter2->unordered != NULL){
					struct packet unordered;
					iter2->unordered->readData(0, &unordered, sizeof(struct packet));
					if(ntohl(received.packet_header.pac_tcphdr.seq)+packet->getSize()-54 == ntohl(unordered.packet_header.pac_tcphdr.seq)){
						Packet * newpacket = allocatePacket(sizeof(struct packet));
						struct packet_header head;
						head.pac_iphdr.saddr = received_daddr;
						head.pac_iphdr.daddr = received_saddr;
						head.pac_tcphdr.source = received_dport;
						head.pac_tcphdr.dest = received_sport;
						head.pac_tcphdr.seq = iter2->seq;
						head.pac_tcphdr.doff = sizeof(struct tcphdr) >> 2;
						head.pac_tcphdr.ack_seq = htonl(ntohl(unordered.packet_header.pac_tcphdr.seq)+iter2->unordered->getSize()-54);
						head.pac_tcphdr.res1 = 0;
						head.pac_tcphdr.res2= 0;
						head.pac_tcphdr.fin = 0;
						head.pac_tcphdr.syn = 0;
						head.pac_tcphdr.rst = 0;
						head.pac_tcphdr.psh = 0;
						head.pac_tcphdr.ack = 1;
						head.pac_tcphdr.urg = 0;
						head.pac_tcphdr.window = received.packet_header.pac_tcphdr.window;
						head.pac_tcphdr.check = 0;
						head.pac_tcphdr.check = htons(~NetworkUtil::tcp_sum(received_daddr, received_saddr, (uint8_t *)&head.pac_tcphdr, 20));

						newpacket->writeData(0, &head, sizeof(struct packet_header));


						// if(ntohl(iter2->ack_seq)==ntohl(received.packet_header.pac_tcphdr.seq)+512){
						// 	return;
						// }
						this->sendPacket("IPv4",newpacket);


						iter2->ack_seq = htonl(ntohl(unordered.packet_header.pac_tcphdr.seq)+iter2->unordered->getSize()-54);
						int read_count = 0;
						if(iter2->read_size<packet->getSize()-54){
							packet->readData(54, iter2->read_buf, iter2->read_size);
							read_count += iter2->read_size;
							iter2->last_byte_read += read_count;
							iter2->last_byte_rcvd += (packet->getSize()-54+iter2->unordered->getSize()-54);
							iter2->read_size = 0;
							iter2->read_offset +=read_count;

							iter2->received_packet_list.push_back(packet);
							iter2->received_packet_list.push_back(iter2->unordered);
							iter2->unordered = 0;

							returnSystemCall(iter2->uuid, read_count);
							return;

						}
						packet->readData(54, iter2->read_buf, packet->getSize()-54);
						read_count += packet->getSize() - 54;
						this->freePacket(packet);

						iter2->last_byte_read += read_count;
						iter2->last_byte_rcvd += (read_count+iter2->unordered->getSize()-54);
						iter2->read_size = 0;
						iter2->received_packet_list.push_back(iter2->unordered);
						iter2->unordered = 0;
						returnSystemCall(iter2->uuid, read_count);
						return;
					}

				}
				Packet * newpacket = allocatePacket(sizeof(struct packet));
				struct packet_header head;
				head.pac_iphdr.saddr = received_daddr;
				head.pac_iphdr.daddr = received_saddr;
				head.pac_tcphdr.source = received_dport;
				head.pac_tcphdr.dest = received_sport;
				head.pac_tcphdr.seq = iter2->seq;
				head.pac_tcphdr.doff = sizeof(struct tcphdr) >> 2;
				head.pac_tcphdr.ack_seq = htonl(ntohl(received.packet_header.pac_tcphdr.seq)+packet->getSize()-54);
				head.pac_tcphdr.res1 = 0;
				head.pac_tcphdr.res2= 0;
				head.pac_tcphdr.fin = 0;
				head.pac_tcphdr.syn = 0;
				head.pac_tcphdr.rst = 0;
				head.pac_tcphdr.psh = 0;
				head.pac_tcphdr.ack = 1;
				head.pac_tcphdr.urg = 0;
				head.pac_tcphdr.window = received.packet_header.pac_tcphdr.window;
				head.pac_tcphdr.check = 0;
				head.pac_tcphdr.check = htons(~NetworkUtil::tcp_sum(received_daddr, received_saddr, (uint8_t *)&head.pac_tcphdr, 20));

				newpacket->writeData(0, &head, sizeof(struct packet_header));


				// if(ntohl(iter2->ack_seq)==ntohl(received.packet_header.pac_tcphdr.seq)+512){
				// 	return;
				// }

				this->sendPacket("IPv4",newpacket);

				iter2->ack_seq = htonl(ntohl(received.packet_header.pac_tcphdr.seq)+packet->getSize()-54);

				int read_count = 0;
				if(iter2->read_size<packet->getSize()-54){
					packet->readData(54, iter2->read_buf, iter2->read_size);
					read_count += iter2->read_size;

					iter2->last_byte_read += read_count;
					iter2->last_byte_rcvd += packet->getSize()-54;
					iter2->read_size = 0;
					iter2->read_offset +=read_count;
					iter2->received_packet_list.push_back(packet);

					returnSystemCall(iter2->uuid, read_count);
					return;

				}

				packet->readData(54, iter2->read_buf, packet->getSize()-54);
				read_count += packet->getSize() - 54;
				this->freePacket(packet);

				iter2->last_byte_read += read_count;
				iter2->last_byte_rcvd += read_count;
				iter2->read_size = 0;

				returnSystemCall(iter2->uuid, read_count);
				return;
			}

			if(iter2->unordered != NULL){

				struct packet unordered;
				iter2->unordered->readData(0, &unordered, sizeof(struct packet));
				if(ntohl(received.packet_header.pac_tcphdr.seq)+packet->getSize()-54 == ntohl(unordered.packet_header.pac_tcphdr.seq)){
					Packet * newpacket = allocatePacket(sizeof(struct packet));
					struct packet_header head;
					head.pac_iphdr.saddr = received_daddr;
					head.pac_iphdr.daddr = received_saddr;
					head.pac_tcphdr.source = received_dport;
					head.pac_tcphdr.dest = received_sport;
					head.pac_tcphdr.seq = iter2->seq;
					head.pac_tcphdr.doff = sizeof(struct tcphdr) >> 2;
					head.pac_tcphdr.ack_seq = htonl(ntohl(unordered.packet_header.pac_tcphdr.seq)+iter2->unordered->getSize()-54);
					head.pac_tcphdr.res1 = 0;
					head.pac_tcphdr.res2= 0;
					head.pac_tcphdr.fin = 0;
					head.pac_tcphdr.syn = 0;
					head.pac_tcphdr.rst = 0;
					head.pac_tcphdr.psh = 0;
					head.pac_tcphdr.ack = 1;
					head.pac_tcphdr.urg = 0;
					head.pac_tcphdr.window = received.packet_header.pac_tcphdr.window;
					head.pac_tcphdr.check = 0;
					head.pac_tcphdr.check = htons(~NetworkUtil::tcp_sum(received_daddr, received_saddr, (uint8_t *)&head.pac_tcphdr, 20));

					newpacket->writeData(0, &head, sizeof(struct packet_header));
					// if(ntohl(iter2->ack_seq)==ntohl(received.packet_header.pac_tcphdr.seq)+512){
						
					// 	return;
					// }

					iter2->ack_seq = htonl(ntohl(unordered.packet_header.pac_tcphdr.seq)+iter2->unordered->getSize()-54);

					this->sendPacket("IPv4",newpacket);
					//this->freePacket(packet);

					iter2->received_packet_list.push_back(packet);
					iter2->received_packet_list.push_back(iter2->unordered);
					iter2->unordered = 0;


					iter2->last_byte_rcvd+=(packet->getSize()-54+iter2->unordered->getSize()-54);
					return;
	
				}

			}



			//if received data -server
			Packet * newpacket = allocatePacket(sizeof(struct packet));
			struct packet_header head;
			head.pac_iphdr.saddr = received_daddr;
			head.pac_iphdr.daddr = received_saddr;
			head.pac_tcphdr.source = received_dport;
			head.pac_tcphdr.dest = received_sport;
			head.pac_tcphdr.seq = iter2->seq;
			head.pac_tcphdr.doff = sizeof(struct tcphdr) >> 2;
			head.pac_tcphdr.ack_seq = htonl(ntohl(received.packet_header.pac_tcphdr.seq)+packet->getSize()-54);
			head.pac_tcphdr.res1 = 0;
			head.pac_tcphdr.res2= 0;
			head.pac_tcphdr.fin = 0;
			head.pac_tcphdr.syn = 0;
			head.pac_tcphdr.rst = 0;
			head.pac_tcphdr.psh = 0;
			head.pac_tcphdr.ack = 1;
			head.pac_tcphdr.urg = 0;
			head.pac_tcphdr.window = received.packet_header.pac_tcphdr.window;
			head.pac_tcphdr.check = 0;
			head.pac_tcphdr.check = htons(~NetworkUtil::tcp_sum(received_daddr, received_saddr, (uint8_t *)&head.pac_tcphdr, 20));

			newpacket->writeData(0, &head, sizeof(struct packet_header));

			
			// if(ntohl(iter2->ack_seq)==ntohl(received.packet_header.pac_tcphdr.seq)+512){
				
			// 	return;
			// }

			// if(iter2->unordered != NULL){

			// 	struct packet unordered;
			// 	iter2->unordered->readData(0, &unordered, sizeof(struct packet));
			// 	if(ntohl(received.packet_header.pac_tcphdr.seq)+packet->getSize()-54 == ntohl(unordered.packet_header.pac_tcphdr.seq)){
			// 		printf("adfafafaaf!!!!!!!!!!!!!!!!!!!!!!!\n");
			// 		iter2->ack_seq = htonl(ntohl(unordered.packet_header.pac_tcphdr.seq)+packet->getSize()-54);
			// 		this->sendPacket("IPv4",newpacket);
			// 		//this->freePacket(packet);
					
			// 		iter2->received_packet_list.push_back(packet);
			// 		iter2->received_packet_list.push_back(iter2->unordered);
			// 		iter2->last_byte_rcvd+=(packet->getSize()-54)+512;
			// 		return;	
			// 	}

			// }



			iter2->ack_seq = htonl(ntohl(received.packet_header.pac_tcphdr.seq)+packet->getSize()-54);

			this->sendPacket("IPv4",newpacket);
			//this->freePacket(packet);

			iter2->received_packet_list.push_back(packet);
			iter2->last_byte_rcvd+=(packet->getSize()-54);
			return;

		}
		else if(iter2->state == ST_LISTEN){

			list<Pennding_element>::iterator iter3;
			iter2->sent_packet_list.pop_front();
			cancelTimer(iter2->timerID);
			b=0;
			for(iter3 = iter2->pennding_list.begin(); iter3 != iter2->pennding_list.end();iter3++){
				if(iter3->addr == received_saddr && iter3->port == received_sport){
					b = 1;
					break;
				}
			}	
			if(b == 0){
				freePacket(packet);
				return;
			}

			if(iter3->state == ST_SYN_RCVD){

				iter2->timerID = 0;
				if(acceptwait.empty()){
					struct Completed_element ce;
					ce.cli_addr = received_saddr;
					ce.cli_port = received_sport;
					ce.ser_addr = received_daddr;
					ce.ser_port = received_dport;
					ce.ack_seq = htonl(ntohl(received.packet_header.pac_tcphdr.seq));
					Completed_list.push_back(ce);
					iter2->pennding_list.erase(iter3);
				}
				else{
					struct Accept_element accepted =  acceptwait.front();


					((struct sockaddr_in *) accepted.addr)->sin_family = AF_INET;
				    ((struct sockaddr_in *) accepted.addr)->sin_port = received_sport;
				    ((struct sockaddr_in *) accepted.addr)->sin_addr.s_addr = received_saddr;

				    *accepted.len = sizeof(struct sockaddr);

					int newsock = createFileDescriptor(accepted.pid);
					struct Sock_element se;
					se.pid = accepted.pid;
					se.fd = newsock;
					se.state = ST_ESTABLISHED;
					se.uuid = accepted.uuid;
					se.cli_addr = received_daddr;
					se.cli_port = received_dport;
					se.ser_addr = received_saddr;
					se.ser_port = received_sport;
					se.ack_seq = htonl(ntohl(received.packet_header.pac_tcphdr.seq));
					se.backlog = 0;
					se.seq = htonl(1);
					Sock_list.push_front(se);

					struct Bind_element be;
					be.pid = accepted.pid;
					be.fd = newsock;
					be.addr = received_saddr;
					be.port = received_sport;
					be.family = AF_INET;
					be.len = sizeof(struct sockaddr);
					Bind_list.push_front(be);
					iter2->pennding_list.erase(iter3);
					acceptwait.pop_front();
					freePacket(packet);

					returnSystemCall(se.uuid, newsock);

				}
			}

		}
		else if(iter2->state == ST_FIN_WAIT1){

			if(iter2->seq != received.packet_header.pac_tcphdr.ack_seq){
				freePacket(packet);
				return;
			}

			iter2->state = ST_FIN_WAIT2;

		}
		else if(iter2->state == ST_CLOSING){

			iter2->state = ST_TIME_WAIT;

			if(iter2->seq != received.packet_header.pac_tcphdr.ack_seq){
				freePacket(packet);
				return;
			}

			struct Sock_element * a= (struct Sock_element *)malloc(sizeof(struct Sock_element));
			a->pid = iter2->pid;
			a->fd = iter2->fd;
			a->state = ST_TIME_WAIT;
			addTimer((void *)a, (Time) SEC);

			// Bind_list.erase(iter);
			// Sock_list.erase(iter2);

			// removeFileDescriptor(iter2->pid, iter2->fd);
			// returnSystemCall(iter2->uuid, 0);

		}
		else if(iter2->state == ST_LAST_ACK){

			if(iter2->seq != received.packet_header.pac_tcphdr.ack_seq){
				freePacket(packet);
				return;
			}

			Bind_list.erase(iter);
			Sock_list.erase(iter2);

			removeFileDescriptor(iter2->pid, iter2->fd);
			returnSystemCall(iter2->uuid, 0);

		}

	}
	//FIN
	else if(received.packet_header.pac_tcphdr.fin ==1){

		uint32_t received_daddr = received.packet_header.pac_iphdr.daddr;
		uint32_t received_dport = received.packet_header.pac_tcphdr.dest;
		uint32_t received_saddr = received.packet_header.pac_iphdr.saddr;
		uint32_t received_sport = received.packet_header.pac_tcphdr.source;



		b=0;
		for(iter = Bind_list.begin(); iter != Bind_list.end();iter++){
			if(iter->addr == received_saddr && iter->port == received_sport){
				b=1;
				break;
			}
		}

		if(b == 0){

			if(b == 0){
				//remove not established socket
				list<Completed_element>::iterator iter3;
				for(iter3 = Completed_list.begin(); iter3 != Completed_list.end();iter3++){
					if(iter3->cli_addr == received_saddr && iter3->cli_port == received_sport){

						Packet * newpacket = allocatePacket(sizeof(struct packet));
						struct packet_header head;
						head.pac_iphdr.saddr = received_daddr;
						head.pac_iphdr.daddr = received_saddr;
						head.pac_tcphdr.source = received_dport;
						head.pac_tcphdr.dest = received_sport;
						head.pac_tcphdr.seq = htonl(1);
						head.pac_tcphdr.doff = sizeof(struct tcphdr) >> 2;
						head.pac_tcphdr.ack_seq = htonl(ntohl(received.packet_header.pac_tcphdr.seq)+1);
						head.pac_tcphdr.res1 = 0;
						head.pac_tcphdr.res2= 0;
						head.pac_tcphdr.fin = 0;
						head.pac_tcphdr.syn = 0;
						head.pac_tcphdr.rst = 0;
						head.pac_tcphdr.psh = 0;
						head.pac_tcphdr.ack = 1;
						head.pac_tcphdr.urg = 0;
						head.pac_tcphdr.window = received.packet_header.pac_tcphdr.window;
						head.pac_tcphdr.check = 0;
						head.pac_tcphdr.check = htons(~NetworkUtil::tcp_sum(received_daddr, received_saddr, (uint8_t *)&head.pac_tcphdr, 20));

						newpacket->writeData(0, &head, sizeof(struct packet_header));

						this->sendPacket("IPv4",newpacket);
						this->freePacket(packet);
						return;
					}
				}
			}

			for(iter = Bind_list.begin(); iter != Bind_list.end();iter++){
				// printf("%x!!!!\n", iter->addr);
				// printf("%x???\n", iter->port);
				// printf("%x***\n", received_daddr);
				// printf("%x^^^\n", received_dport);
				if((iter->addr == received_daddr || iter->addr == INADDR_ANY) && iter->port == received_dport){
					b=1;
					break;
				}
			}
			
		}

		b=0;
		for(iter2 = Sock_list.begin(); iter2 != Sock_list.end();iter2++){
			if(iter2->pid == iter->pid && iter2->fd == iter->fd){
				b = 1;
				break;
			}
		}	
		if(b == 0){

			freePacket(packet);
			return;
		}


		list<Pennding_element>::iterator iter4;

		for(iter4 = iter2->pennding_list.begin(); iter4 != iter2->pennding_list.end();iter4++){
			if(iter4->addr == received_saddr && iter->port == received_sport){
				b=1;
				iter2->pennding_list.erase(iter4);
				return;
			}
		}

		if(iter2->state == ST_ESTABLISHED){
			iter2->state = ST_CLOSE_WAIT;

			Packet * newpacket = allocatePacket(sizeof(struct packet));
			struct packet_header head;
			head.pac_iphdr.saddr = received_daddr;
			head.pac_iphdr.daddr = received_saddr;
			head.pac_tcphdr.source = received_dport;
			head.pac_tcphdr.dest = received_sport;
			head.pac_tcphdr.seq = iter2->seq;
			head.pac_tcphdr.doff = sizeof(struct tcphdr) >> 2;
			head.pac_tcphdr.ack_seq = htonl(ntohl(received.packet_header.pac_tcphdr.seq)+1);
			head.pac_tcphdr.res1 = 0;
			head.pac_tcphdr.res2=0;
			head.pac_tcphdr.fin = 0;
			head.pac_tcphdr.syn = 0;
			head.pac_tcphdr.rst = 0;
			head.pac_tcphdr.psh = 0;
			head.pac_tcphdr.ack = 1;
			head.pac_tcphdr.urg = 0;
			head.pac_tcphdr.window = received.packet_header.pac_tcphdr.window;
			head.pac_tcphdr.check = 0;
			head.pac_tcphdr.check = htons(~NetworkUtil::tcp_sum(received_daddr, received_saddr, (uint8_t *)&head.pac_tcphdr, 20));

			newpacket->writeData(0, &head, sizeof(struct packet_header));

			struct Sock_element * a= (struct Sock_element *)malloc(sizeof(struct Sock_element));
			a->pid = iter2->pid;
			a->fd = iter2->fd;
			a->state = ST_TIME_WAIT;
			a->unordered = newpacket;
			addTimer((void *)a, (Time)SEC);

			//this->sendPacket("IPv4",newpacket);
			this->freePacket(packet);

		}
		else if(iter2->state == ST_FIN_WAIT1){

			iter2->state = ST_CLOSING;

			Packet * newpacket = allocatePacket(sizeof(struct packet));
			struct packet_header head;
			head.pac_iphdr.saddr = received_daddr;
			head.pac_iphdr.daddr = received_saddr;
			head.pac_tcphdr.source = received_dport;
			head.pac_tcphdr.dest = received_sport;
			head.pac_tcphdr.seq = iter2->seq;
			head.pac_tcphdr.doff = sizeof(struct tcphdr) >> 2;
			head.pac_tcphdr.ack_seq = htonl(ntohl(received.packet_header.pac_tcphdr.seq)+1);
			head.pac_tcphdr.res1 = 0;
			head.pac_tcphdr.res2=0;
			head.pac_tcphdr.fin = 0;
			head.pac_tcphdr.syn = 0;
			head.pac_tcphdr.rst = 0;
			head.pac_tcphdr.psh = 0;
			head.pac_tcphdr.ack = 1;
			head.pac_tcphdr.urg = 0;
			head.pac_tcphdr.window = received.packet_header.pac_tcphdr.window;
			head.pac_tcphdr.check = 0;
			head.pac_tcphdr.check = htons(~NetworkUtil::tcp_sum(received_daddr, received_saddr, (uint8_t *)&head.pac_tcphdr, 20));

			newpacket->writeData(0, &head, sizeof(struct packet_header));

			this->sendPacket("IPv4",newpacket);
			this->freePacket(packet);

		}
		else if(iter2->state == ST_FIN_WAIT2){

			iter2->state = ST_TIME_WAIT;

			Packet * newpacket = allocatePacket(sizeof(struct packet));
			struct packet_header head;
			head.pac_iphdr.saddr = received_daddr;
			head.pac_iphdr.daddr = received_saddr;
			head.pac_tcphdr.source = received_dport;
			head.pac_tcphdr.dest = received_sport;
			head.pac_tcphdr.seq = iter2->seq;
			head.pac_tcphdr.doff = sizeof(struct tcphdr) >> 2;
			head.pac_tcphdr.ack_seq = htonl(ntohl(received.packet_header.pac_tcphdr.seq)+1);
			head.pac_tcphdr.res1 = 0;
			head.pac_tcphdr.res2=0;
			head.pac_tcphdr.fin = 0;
			head.pac_tcphdr.syn = 0;
			head.pac_tcphdr.rst = 0;
			head.pac_tcphdr.psh = 0;
			head.pac_tcphdr.ack = 1;
			head.pac_tcphdr.urg = 0;
			head.pac_tcphdr.window = received.packet_header.pac_tcphdr.window;
			head.pac_tcphdr.check = 0;
			head.pac_tcphdr.check = htons(~NetworkUtil::tcp_sum(received_daddr, received_saddr, (uint8_t *)&head.pac_tcphdr, 20));

			newpacket->writeData(0, &head, sizeof(struct packet_header));

			this->sendPacket("IPv4",newpacket);
			this->freePacket(packet);


			struct Sock_element * a= (struct Sock_element *)malloc(sizeof(struct Sock_element));
			a->pid = iter2->pid;
			a->fd = iter2->fd;
			a->state = ST_TIME_WAIT;
			addTimer((void *)a, (Time)SEC);

			// Bind_list.erase(iter);
			// Sock_list.erase(iter2);

			// removeFileDescriptor(iter2->pid, iter2->fd);
			// returnSystemCall(iter2->uuid, 0);

		}


	}


}

void TCPAssignment::timerCallback(void* payload)
{
	//printf("aaaaaaaaaaaa\n");

	struct Sock_element * se = (struct Sock_element*) payload;



	if(se->state == ST_TIME_WAIT){
		list<Bind_element>::iterator iter;
		for(iter = Bind_list.begin(); iter != Bind_list.end();iter++){
			if(iter->pid == se->pid && iter->fd ==se->fd){
				Bind_list.erase(iter);
				break;
			}	
		}

	    list<Sock_element>::iterator iter2;
		for(iter2 = Sock_list.begin(); iter2 != Sock_list.end();iter2++){
			if(iter2->pid == se->pid && iter2->fd ==se->fd){
				Sock_list.erase(iter2);
				break;
			}	
		}
		removeFileDescriptor(se->pid, se->fd);
		returnSystemCall(se->uuid, 0);
	}
	else if(se->state == ST_ESTABLISHED){
		list<Sock_element>::iterator iter2;
		int b=0;
		for(iter2 = Sock_list.begin(); iter2 != Sock_list.end();iter2++){
			if(iter2->pid == se->pid && iter2->fd ==se->fd){
				b=1;
				break;
			}	
		}
		if(b==0){
			return;
		}
		//printf("ddddd\n");

		if(iter2->sent_packet_list.size()>0){
			list<Packet *>::iterator iter3;
			struct Sock_element * a= (struct Sock_element *)malloc(sizeof(struct Sock_element));
			a->pid = iter2->pid;
			a->fd = iter2->fd;
			a->state = ST_ESTABLISHED;
			//printf("eeee\n");

			int i;
			//printf("%d\n",iter2->sent_packet_list.size());
			for(i=0;i<iter2->sent_packet_list.size();i++){
				Packet *storing = this->clonePacket(iter2->sent_packet_list.front());
				Packet *sending = iter2->sent_packet_list.front();
				iter2->sent_packet_list.pop_front();
				iter2->sent_packet_list.push_back(storing);
				this->sendPacket("IPv4", sending);	
			}
			//		printf("ffff\n");
			iter2->timerID = addTimer(a, (Time) SEC/10);


			// for(iter3 = iter2->sent_packet_list.begin(); iter3 != iter2->sent_packet_list.end();iter3++){
			// 	Packet *storing = this->clonePacket(iter2->sent_packet_list.front());
			// 	Packet *sending = iter2->sent_packet_list.front();
			// 	iter2->sent_packet_list.pop_front();
			// 	iter2->sent_packet_list.push_front(storing);

			// 	this->sendPacket("IPv4", *iter3);	
			// }
			return;
		}

	}
	else if(se->state == ST_LISTEN){

		list<Sock_element>::iterator iter2;
		int b=0;
		for(iter2 = Sock_list.begin(); iter2 != Sock_list.end();iter2++){
			if(iter2->pid == se->pid && iter2->fd ==se->fd){
				b=1;
				break;
			}	
		}
		if(b==0){
			return;
		}

		if(iter2->sent_packet_list.size()>0){
			list<Packet *>::iterator iter3;
			struct Sock_element * a= (struct Sock_element *)malloc(sizeof(struct Sock_element));
			a->pid = iter2->pid;
			a->fd = iter2->fd;
			a->state = ST_LISTEN;
			iter2->timerID = addTimer(a, (Time) SEC/100);
			Packet *storing = this->clonePacket(iter2->sent_packet_list.front());
			Packet *sending = iter2->sent_packet_list.front();
			iter2->sent_packet_list.pop_front();
			iter2->sent_packet_list.push_front(storing);
			this->sendPacket("IPv4", sending);	
			return;
		}
	}
	else if(se->state == ST_CLOSE_WAIT){
		this->sendPacket("IPv4", se->unordered);
		return;
	}
	else if(se->state == ST_SYN_SENT){


		list<Bind_element>::iterator iter;
		list<Sock_element>::iterator iter2;
		int b=0;
		for(iter2 = Sock_list.begin(); iter2 != Sock_list.end();iter2++){
			if(iter2->pid == se->pid && iter2->fd ==se->fd){
				b=1;
				break;
			}	
		}
		if(b==0){
			return;
		}
		b= 0;
		for(iter = Bind_list.begin(); iter != Bind_list.end();iter++){
			if(iter->pid == se->pid && iter->fd == se->fd){
				b=1;
				break;
			}
		}
		if(b==0){
			return;
		}

		if(iter2->state == ST_SYN_SENT){


			Packet * storing = this->clonePacket(se->unordered);

			struct Sock_element * a= (struct Sock_element *)malloc(sizeof(struct Sock_element));
			a->pid = iter2->pid;
			a->fd = iter2->fd;
			a->state = ST_SYN_SENT;
			a->unordered = storing;
			addTimer((void *)a, (Time)SEC/10);
			this->sendPacket("IPv4", se->unordered);

			}
		

	}

}

}
/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <list>
using namespace std;

#include <E/E_TimerModule.hpp>


namespace E
{

enum SOCK_STATE {ST_CLOSED, ST_LISTEN, ST_SYN_SENT, ST_SYN_RCVD, ST_ESTABLISHED, ST_CLOSE_WAIT, ST_LAST_ACK, ST_FIN_WAIT1, ST_FIN_WAIT2, ST_CLOSING, ST_TIME_WAIT};

struct Sock_element{
	int pid;
	int fd;
	int state;
	int backlog;
	E::UUID uuid;
	uint32_t cli_addr;
	uint32_t cli_port;
	uint32_t ser_addr;	
	uint16_t ser_port;
	uint32_t seq;
	uint32_t ack_seq;
	list<struct Pennding_element> pennding_list;

	uint32_t send_base=0;
	uint32_t last_byte_read=1;
	uint32_t last_byte_rcvd=1;
	uint32_t last_byte_sent = 0;
	uint32_t last_byte_acked = 0;

	uint32_t rwnd =51200;
	uint32_t cwnd = 512;

	//uint32_t ssthresh = 1;

	list<Packet *> received_packet_list;
	list<Packet *> sent_packet_list;

	uint32_t read_size=0;
	char * read_buf;
	uint32_t read_offset =0;

	uint32_t write_size=0;
	char * write_buf;

	uint32_t timerID=0;

	Packet * unordered = NULL;

}__attribute__((packed));

struct Pennding_element{
	uint32_t addr;
	uint32_t port;
	int state;
	int seq;
}__attribute__((packed));

struct Bind_element{
	int pid;
	int fd;
	uint32_t addr;
	uint16_t port;
	uint16_t family;
	socklen_t len;
}__attribute__((packed));

struct Accept_element{
	int pid;
	int fd;
	E::UUID uuid;
	struct sockaddr * addr;
	socklen_t * len;
}__attribute__((packed));

struct Completed_element{
	uint32_t cli_addr;
	uint32_t ser_addr;
	uint32_t cli_port;
	uint32_t ser_port;
	uint32_t ack_seq;
}__attribute__((packed));

struct ethdr{
	char desmac[6];
	char sourmac[6];
	short type;
}__attribute__((packed));

struct packet_header{
	struct ethdr pac_ethdr;
	struct iphdr pac_iphdr;
	struct tcphdr pac_tcphdr;
}__attribute__((packed));

struct packet{
	struct packet_header packet_header;
}__attribute__((packed));


class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:

private:
	virtual void timerCallback(void* payload) final;

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
	virtual void syscall_socket(UUID syscallUUID, int pid, int param1_int, int param2_int);
	virtual void syscall_close(UUID syscallUUID, int pid, int param1_int);
	virtual void syscall_bind(UUID syscallUUID, int pid, int param1_int, struct sockaddr * param2_ptr, socklen_t param3_int );
	virtual void syscall_getsockname(UUID syscallUUID, int pid, int param1_int, struct sockaddr * param2_ptr, socklen_t * param3_int );
	virtual void syscall_connect(UUID syscallUUID, int pid, int fd, struct sockaddr* addr, socklen_t len);
	virtual void syscall_listen(UUID syscallUUID, int pid, int fd, int backlog);
	virtual void syscall_accept(UUID syscallUUID, int pid, int fd, struct sockaddr* addr, socklen_t * len);
	virtual void syscall_getpeername(UUID syscallUUID, int pid, int fd, struct sockaddr* addr, socklen_t * len);
	virtual void syscall_read(UUID syscallUUID, int pid, int fd, void* addr, int size);
	virtual void syscall_write(UUID syscallUUID, int pid, int fd, void* addr, int size);
	list<Bind_element> Bind_list;
	list<Sock_element> Sock_list;
	list<Completed_element> Completed_list;
	list<Accept_element> acceptwait;
protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */

//tcpip.h class definition
#pragma once
#include <string>
#include<optional>
#include <arpa/inet.h>
#define BUF_SIZE 4096

class Tcpip 
{//c library wrapper 
public:
	Tcpip(int port = 2001);
	virtual ~Tcpip();
	void send(const std::string& s, int fd = 0);
//	void send(int n);
	std::optional<std::string> recv(int fd = 0);

protected:
	int server_fd;///<server_fd입니다.
	int client_fd;
	struct sockaddr_in server_addr, client_addr;
	char buffer[BUF_SIZE];

private:
};


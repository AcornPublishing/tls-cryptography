#pragma once
#include<map>
#include<functional>
#include"tcpip.h"

class Vrecv : public Tcpip
{//virtual class that provide interface to get recv work just as expected
public:
	Vrecv(int port);
	std::optional<std::string> recv(int fd=0);
	//check content length header and get one full request
protected:
	virtual int get_full_length(const std::string& s);//define this to make recv adapt to environment
};

class Http : public Vrecv
{
public:
	Http(int port);

protected:
	int get_full_length(const std::string& s);
};

class TlsLayer : public Vrecv
{
public:
	TlsLayer(int port);

protected:
	int get_full_length(const std::string& s);
};

class Client : public Http
{
public:
	Client(std::string ip = "127.0.0.1", int port = 2001); ///<constructor
private:
	std::string get_addr(std::string host);
};

class Server : public Http
{
public:
	Server(int port = 2001, unsigned int time_out = 600, int queue_limit = 10,
			std::string end_string = "end");
	void start(std::function<std::string(std::string)> f);
	void nokeep_start(std::function<std::string(std::string)> f);

protected:
	std::string end_string;
	int time_out;
};


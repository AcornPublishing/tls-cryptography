#include<iostream>
#include"tcpip/server.h"
using namespace std;

int main(int ac, char **av) {
	Client cl{"localhost", 2002};
	cl.send("GET /");
	cout << *cl.recv() << endl;
}


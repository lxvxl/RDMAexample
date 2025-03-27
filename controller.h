#ifndef CONTROLLER_H
#define CONTROLLER_H

#include <string>

class Controller {
public:
    Controller(const std::string &ip, int port, bool isServer, bool isMaster);
    ~Controller();

    bool sockConnect(); // 尝试连接或等待客户端连接
    bool sendMessage(const std::string &message);
    std::string receiveMessage();

private:
    std::string ip_;
    int port_;
    bool isServer_;
    int sockfd_;
    bool isMaster_;
};

#endif // CONTROLLER_H

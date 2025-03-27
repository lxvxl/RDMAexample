#include "controller.h"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <chrono>
#include <thread>

Controller::Controller(const std::string &ip, int port, bool isServer, bool isMaster)
    : ip_(ip), port_(port), isServer_(isServer), sockfd_(-1), isMaster_(isMaster) {}

Controller::~Controller() {
    if (sockfd_ >= 0) close(sockfd_);
}

bool Controller::sockConnect() {
    sockfd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd_ < 0) {
        std::cerr << "Failed to create socket\n";
        return false;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_);
    addr.sin_addr.s_addr = isServer_ ? INADDR_ANY : inet_addr(ip_.c_str());

    // 如果是服务器模式，绑定和监听
    if (isServer_) {
        if (bind(sockfd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            std::cerr << "Bind failed\n";
            return false;
        }
        if (listen(sockfd_, 1) < 0) {
            std::cerr << "Listen failed\n";
            return false;
        }
        std::cout << "Server initialized, waiting for connections...\n";

        // 等待客户端连接
        sockaddr_in clientAddr{};
        socklen_t clientLen = sizeof(clientAddr);
        while (true) {
            int clientSock = accept(sockfd_, (struct sockaddr*)&clientAddr, &clientLen);
            if (clientSock >= 0) {
                std::cout << "Client connected\n";
                sockfd_ = clientSock; // 使用客户端的套接字进行通信
                return true;
            } else {
                std::cerr << "Accept failed, retrying in 1 second...\n";
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
    } else {
        // 如果是客户端模式，尝试连接服务器
        while (true) {
            if (connect(sockfd_, (struct sockaddr*)&addr, sizeof(addr)) >= 0) {
                return true;
            } else {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }
    }
}

bool Controller::sendMessage(const std::string &message) {
    if (send(sockfd_, message.c_str(), message.size(), 0) < 0) {
        std::cerr << "Send failed\n";
        return false;
    }
    return true;
}

std::string Controller::receiveMessage() {
    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));
    ssize_t received = recv(sockfd_, buffer, sizeof(buffer), 0);
    if (received < 0) {
        std::cerr << "Receive failed\n";
        return "";
    }
    return std::string(buffer, received);
}

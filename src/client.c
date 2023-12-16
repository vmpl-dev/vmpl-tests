#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "benchmark.h"

int vmpl_client(int argc, char *argv[])
{
    int sock = 0, valread;
    struct sockaddr_in serv_addr;
    char *hello = "Hello from client";
    char buffer[1024] = {0};

    // 创建socket文件描述符
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Socket creation error \n");
        return -1;
    }

    // 设置服务器地址结构
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // 将IPv4地址从点分十进制转换为二进制格式
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0)
    {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    // 连接到服务器
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("\nConnection Failed \n");
        return -1;
    }

    // 发送消息给服务器
    size_t hello_len = strlen(hello);
    send(sock, hello, hello_len, 0);
    printf("Hello message sent from client\n");

    // 读取服务器回复的消息
    valread = recv(sock, buffer, 1024, 0);
    if (valread == -1)
    {
        printf("Error reading from socket");
        return -1;
    }
    printf("Server received: %s\n", buffer);

    return 0;
}
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void) {
    int fd = open("/tmp/testfile.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        const char *msg = "hello from file\n";
        write(fd, msg, strlen(msg));
        close(fd);
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock >= 0) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(80);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        connect(sock, (struct sockaddr *)&addr, sizeof(addr));
        close(sock);
    }

    const char *hello = "привет\n";
    write(1, hello, strlen(hello));

    return 0;
}

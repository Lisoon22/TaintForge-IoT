#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define TARGET_IP "198.51.100.10"
#define TARGET_PORT 48101
#define EXPECTED_RESPONSE "world"

static int send_all(
    int fd,
    const unsigned char *buffer,
    size_t size
) {
    size_t offset = 0;

    while (offset < size) {
        ssize_t written = send(
            fd,
            buffer + offset,
            size - offset,
            0
        );

        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }

            perror("send");
            return -1;
        }

        if (written == 0) {
            fprintf(stderr, "send returned zero\n");
            return -1;
        }

        offset += (size_t)written;
    }

    return 0;
}

int main(void) {
    const unsigned char request[] = "hello";
    unsigned char response[64];

    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0) {
        perror("socket");
        return 10;
    }

    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));

    address.sin_family = AF_INET;
    address.sin_port = htons(TARGET_PORT);

    if (
        inet_pton(
            AF_INET,
            TARGET_IP,
            &address.sin_addr
        )
        != 1
    ) {
        fprintf(stderr, "inet_pton failed\n");
        close(fd);
        return 11;
    }

    if (
        connect(
            fd,
            (struct sockaddr *)&address,
            sizeof(address)
        )
        < 0
    ) {
        perror("connect");
        close(fd);
        return 12;
    }

    if (
        send_all(
            fd,
            request,
            sizeof(request) - 1
        )
        != 0
    ) {
        close(fd);
        return 13;
    }

    /*
     * The local mock C2 reads until client EOF before replying.
     * We close only the write half of the TCP connection.
     */
    if (shutdown(fd, SHUT_WR) < 0) {
        perror("shutdown");
        close(fd);
        return 14;
    }

    ssize_t received = recv(
        fd,
        response,
        sizeof(response),
        0
    );

    if (received < 0) {
        perror("recv");
        close(fd);
        return 15;
    }

    if (received > 0) {
        ssize_t stdout_written = write(
            STDOUT_FILENO,
            response,
            (size_t)received
        );

        if (stdout_written != received) {
            perror("write");
            close(fd);
            return 16;
        }

        (void)write(STDOUT_FILENO, "\n", 1);
    }

    close(fd);

    if (
        received != 5
        || memcmp(
            response,
            EXPECTED_RESPONSE,
            5
        )
        != 0
    ) {
        fprintf(stderr, "unexpected response\n");
        return 17;
    }

    return 0;
}

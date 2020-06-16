#include "net_util.h"
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static int fcntl_set(int fd, int flag)
{
	int oldflags = fcntl(fd, F_GETFD, 0);
	/* If reading the flags failed, return error indication now. */
	if (oldflags < 0)
		return oldflags;
	return fcntl(fd, F_SETFD, oldflags | flag);
}

static int fcntl_unset(int fd, int flag)
{
	int oldflags = fcntl(fd, F_GETFD, 0);
	/* If reading the flags failed, return error indication now. */
	if (oldflags < 0)
		return oldflags;
	return fcntl(fd, F_SETFD, oldflags & ~flag);
}

int set_tcp_nodelay(int fd, int nodelay)
{
	return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(int));
}
int set_tcp_quickack(int fd, int qack)
{
    return setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &qack, sizeof(int));
}

int set_tcp_notsent_lowat(int fd, int bytes)
{
    return setsockopt(fd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, &bytes, sizeof(int));
}

int get_tcp_notsent_lowat(int fd)
{
    int bytes;
    socklen_t optlen = sizeof(int);
    int ret = getsockopt(fd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, &bytes, &optlen);
    if (!ret)
        return bytes;
    return -1;
}

int set_socket_max_pacing_rate(int fd, int rate)
{
    return setsockopt(fd, SOL_SOCKET, SO_MAX_PACING_RATE,
                      &rate, sizeof(rate));
}

int set_socket_reuseport(int fd, int reuse)
{
	return setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(int));
}

int set_socket_keepalive(int fd, int keepalive)
{
	return setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(int));
}

int set_nonblock(int fd, int nonblock)
{
    return ioctl(fd, FIONBIO, &nonblock);
}

int set_cloexec(int fd, int cloexec)
{
    if (cloexec)
        return fcntl_set(fd, FD_CLOEXEC);
    else
        return fcntl_unset(fd, FD_CLOEXEC);
}

int get_socket_error(int fd)
{
	int err;
	socklen_t len = sizeof(int);
	int ret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
	if (ret == 0)
		return err;
	return 0;
}

int set_socket_send_buf_size(int fd, int size)
{
    size /= 2; // kernel will double the value
    return setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(int));
}

int get_socket_send_buf_size(int fd, int *size)
{
    socklen_t len = sizeof(int);
    return getsockopt(fd, SOL_SOCKET, SO_SNDBUF, size, &len);
}

int set_socket_recv_buf_size(int fd, int size)
{
    size /= 2; // kernel will double the value
    return setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(int));
}

int set_ip_tos(int fd, int dscp_class)
{
    int tos = (dscp_class << 2);
    return setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(int));
}
int new_and_bind_socket(const char *ip, int port)
{
    int ret;

    // listen on all interfaces
    if (!ip || !strcmp(ip, "0.0.0.0") || !strcmp(ip, "::")) {
        int sock = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (sock == -1)
            return -1;
        struct sockaddr_in6 addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(port);
        addr.sin6_addr = in6addr_any;

        set_socket_reuseport(sock, 1);
        ret = bind(sock, &addr, (socklen_t)sizeof(addr));
        if (ret == -1) {
            close(sock);
            return -1;
        }
        return sock;
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE;

    struct addrinfo* r = NULL;
    char sport[8];
    snprintf(sport, sizeof(sport), "%d", port);
    if (getaddrinfo(ip, sport, &hints, &r) != 0) {
        return -1;
    }

    int sock = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
    if (sock == -1) {
        freeaddrinfo(r);
        return -1;
    }
    set_socket_reuseport(sock, 1);
    ret = bind(sock, r->ai_addr, r->ai_addrlen);
    if (ret == -1) {
        close(sock);
        freeaddrinfo(r);
        return -1;
    }
    freeaddrinfo(r);
    return sock;
}

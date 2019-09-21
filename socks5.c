#define _POSIX_C_SOURCE 200112L

#include <unistd.h>
#include <sys/epoll.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <malloc.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <assert.h>

#include "buff.h"

#if (EAGAIN != EWOULDBLOCK)
	#define EAGAIN_EWOULDBLOCK EAGAIN : case EWOULDBLOCK
#else
	#define EAGAIN_EWOULDBLOCK EAGAIN
#endif

#define LOG(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__); fprintf(stderr, "\n")

typedef struct sockaddr sockaddr_t;
typedef struct sockaddr_in sockaddr_in_t;
typedef struct sockaddr_in6 sockaddr_in6_t;
typedef struct addrinfo addrinfo_t;
typedef struct epoll_event epoll_event_t;

typedef void read_cb(int fd, void *ud);
typedef void write_cb(int fd, void *ud);

#define INIT_BUFF_CAP 1024

#define MAX_UNAME_LEN 20
#define MAX_PASSWD_LEN 20
#define BLACKLOG 1024
#define MAX_EPOLL_EVENTS 64

typedef enum tunnel_state {
	open_state,
	auth_state,
	request_state,
	connecting_state, // connecting to remote
	connected_state,  // connected to remote
} tunnel_state_t;

typedef struct open_protocol {
	uint8_t ver;
	uint8_t nmethods;
	uint8_t methods[255];
} open_protocol_t;

typedef struct auth_protocol {
	uint8_t ver;
	uint8_t ulen;
	char uname[255];
	uint8_t plen;
	char passwd[255];
} auth_protocol_t;

typedef struct request_protocol {
	uint8_t ver;
	uint8_t cmd;
	uint8_t rsv;
	uint8_t atyp;
	uint8_t domainlen;
	char addr[255];
	uint16_t port;
} request_protocol_t;

typedef struct sock sock_t;
typedef struct tunnel {
	sock_t *client_sock;
	sock_t *remote_sock;

	tunnel_state_t state;
	open_protocol_t op;
	auth_protocol_t ap;
	request_protocol_t rp;
	size_t read_count;
	int closed;
} tunnel_t;

typedef enum sock_state {
	sock_connecting,
	sock_connected,
	sock_halfclosed,
	sock_closed,
} sock_state_t;

struct sock {
	int fd;
	read_cb *read_handle;
	write_cb *write_handle;
	buff_t *read_buff;
	buff_t *write_buff;
	tunnel_t *tunnel;
	sock_state_t state;
	int isclient;
};

typedef struct server {
	int listenfd;
	read_cb *read_handle;
	int epollfd;
	char username[255];
	char passwd[255];
} server_t;

server_t SERVER;


static tunnel_t* tunnel_create(int cap);
static void tunnel_release(tunnel_t *tunnel);
static void tunnel_shutdown(tunnel_t *tunnel);
static void tunnel_read_handle(int fd, void *ud);
static void tunnel_write_handle(int fd, void *ud);
static int tunnel_open_handle(tunnel_t *tunnel);
static int tunnel_auth_handle(tunnel_t *tunnel);
static int tunnel_request_handle(tunnel_t *tunnel);
static int tunnel_connecting_handle(tunnel_t *tunnel);
static int tunnel_connected_handle(tunnel_t *tunnel, int client);
static int tunnel_write_client(tunnel_t *tunnel, void *src, size_t size);

static int epoll_add(sock_t *sock)
{
	epoll_event_t event;
	event.events = EPOLLIN;
	event.data.ptr = sock;
	return epoll_ctl(SERVER.epollfd, EPOLL_CTL_ADD, sock->fd, &event);
}

static int epoll_del(sock_t *sock)
{
	epoll_event_t event;
	return epoll_ctl(SERVER.epollfd, EPOLL_CTL_DEL, sock->fd, &event);
}

static int epoll_modify(sock_t *sock, int writable, int readable)
{
	epoll_event_t event;
	event.data.ptr = sock;
	event.events = (writable ? EPOLLOUT : 0) | (readable ? EPOLLIN : 0);
	return epoll_ctl(SERVER.epollfd, EPOLL_CTL_MOD, sock->fd, &event);
}

static sock_t* sock_create(int fd, sock_state_t state, int isclient, tunnel_t * tunnel)
{
	sock_t *sock = (sock_t*)malloc(sizeof(*sock));
	if (sock == NULL) return NULL;
	memset(sock, 0, sizeof(*sock));

	buff_t *read_buff = buff_create(INIT_BUFF_CAP);
	if (read_buff == NULL) return NULL;

	buff_t *write_buff = buff_create(INIT_BUFF_CAP);
	if (write_buff == NULL) {
		buff_release(read_buff);
		free(sock);
		return NULL;
	}

	sock->read_buff = read_buff;
	sock->write_buff = write_buff;
	sock->tunnel = tunnel;
	sock->fd = fd;
	sock->read_handle = tunnel_read_handle;
	sock->write_handle = tunnel_write_handle;
	sock->state = state;
	sock->isclient = isclient;
	return sock;
}

static void sock_release(sock_t *sock)
{
	tunnel_t *tunnel = sock->tunnel;
	
	buff_release(sock->write_buff);
	buff_release(sock->read_buff);

	if (sock->isclient) tunnel->client_sock = NULL;
	else tunnel->remote_sock = NULL;
	epoll_del(sock);
	close(sock->fd);
	free(sock);

	// when both client and remote sock release
	// release tunnel
	if (tunnel->remote_sock == NULL && tunnel->client_sock == NULL) {
		tunnel_release(tunnel);
	}
}

/*
 * Receive rst or no more data to send or invalid peer, we should release sock
 * */
static void sock_force_shutdown(sock_t *sock)
{
	sock_release(sock);
}

/*
 * Receive fin, do not receive again,
 * If Append read_buff to other write_buff,
 * If write_buff not empty, we shoould still send data,
 * Otherwise force shutdown
 * */
static void sock_shutdown(sock_t *sock)
{
	sock->state = sock_halfclosed;

	tunnel_t *tunnel = sock->tunnel;
	// forward left data
	if (tunnel->state == connected_state) {
		if (sock->isclient && tunnel->remote_sock != NULL)
			buff_concat(tunnel->remote_sock->write_buff, sock->read_buff);
		else if(tunnel->client_sock != NULL)
			buff_concat(tunnel->client_sock->write_buff, sock->read_buff);
	}

	int writable = buff_readable(sock->write_buff) > 0;
	if (writable) epoll_modify(sock, writable, 0);
	else sock_force_shutdown(sock);
}

static int sock_nonblocking(int fd)
{
	int flag;
	if ((flag = fcntl(fd, F_GETFL, 0)) < 0) return -1;
	if ((flag = fcntl(fd, F_SETFL, flag | O_NONBLOCK)) < 0) return -1;
	return flag;
}

static int sock_keepalive(int fd)
{
	int keepalive = 1;
	return setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
}

static tunnel_t* tunnel_create(int fd)
{
	sock_nonblocking(fd);
	sock_keepalive(fd);

	tunnel_t *tunnel = (tunnel_t*)malloc(sizeof(*tunnel));
	if (tunnel == NULL) {
		close(fd);
		return NULL;
	}
	memset(tunnel, 0, sizeof(*tunnel));

	sock_t *client_sock = sock_create(fd, sock_connected, 1, tunnel);
	if (client_sock == NULL) {
		free(tunnel);
		close(fd);
		return NULL;
	}

	tunnel->state = open_state;
	tunnel->client_sock = client_sock;
	tunnel->read_count = 0;
	tunnel->closed = 0;

	epoll_add(client_sock);

	return tunnel;
}

static void tunnel_shutdown(tunnel_t *tunnel)
{
	if (tunnel->client_sock != NULL) sock_shutdown(tunnel->client_sock);
	if (tunnel->remote_sock != NULL) sock_shutdown(tunnel->remote_sock);
}

static void tunnel_release(tunnel_t *tunnel)
{
	free(tunnel);
}

static void tunnel_read_handle(int fd, void *ud)
{
	sock_t *sock = (sock_t*)ud;
	tunnel_t *tunnel = sock->tunnel;

	int n = buff_readfd(sock->read_buff, fd);
	if (n < 0) {
		switch (errno) {
			case EINTR:
			case EAGAIN_EWOULDBLOCK:
				break;
			default:
				goto shutdown;
		}
	
	} else if (n == 0) goto shutdown;

	switch(tunnel->state) {
		case open_state:
			if (tunnel_open_handle(tunnel) < 0) goto force_shutdown;
			break;
		case auth_state:
			if (tunnel_auth_handle(tunnel) < 0) goto force_shutdown;
			break;
		case request_state:
			if (tunnel_request_handle(tunnel) < 0) goto force_shutdown;
			break;
		case connecting_state:
			assert(sock->isclient == 0);
			if (tunnel_connecting_handle(tunnel) < 0) goto tunnel_shutdown;
			break;
		case connected_state:
			if (tunnel_connected_handle(tunnel, sock->isclient) < 0) goto tunnel_shutdown;
			break;
		default:
			assert(0);
			break;
	}
	return;

force_shutdown: // peer invalid
	sock_force_shutdown(sock);
	return;

shutdown: // half closed
	sock_shutdown(sock);
	return;

tunnel_shutdown: // half closed both client and remote
	tunnel_shutdown(tunnel);
}

static void tunnel_write_handle(int fd, void *ud)
{
	sock_t *sock = (sock_t *)ud;
	tunnel_t *tunnel = sock->tunnel;
	
	if (buff_readable(sock->write_buff) > 0) {
		int n = buff_writefd(sock->write_buff, fd);
		if (n <= 0) {
			switch (errno) {
				case EINTR:
				case EAGAIN_EWOULDBLOCK:
					break;
				default:
					goto force_shutdown;
			}
		} 
	} else if (sock->state == sock_halfclosed) {
		goto force_shutdown;
	}

	if (tunnel->state == connecting_state) {
		assert(sock->isclient == 0);

		if (tunnel_connecting_handle(tunnel) < 0) goto tunnel_shutdown;
	}

	int writable = buff_readable(sock->write_buff) > 0;
	epoll_modify(sock, writable, 1);

	return;

tunnel_shutdown:
	tunnel_shutdown(tunnel);
	return;

force_shutdown:
	sock_force_shutdown(sock);
	return;
}

// |VER(1)|NMETHODS(1)|METHODS(1-255)|
static int tunnel_open_handle(tunnel_t* tunnel)
{
	buff_t *buff = tunnel->client_sock->read_buff;
	open_protocol_t *op = &tunnel->op;
	size_t *nreaded = &tunnel->read_count;
	size_t nheader = sizeof(op->ver) + sizeof(op->nmethods);

	if (*nreaded == 0) goto header;
	else if(*nreaded == nheader) goto methods;
	else assert(0);

header:
	// VER(1)|NMETHODS(1)
	if (buff_readable(buff) >= nheader) {
		buff_read(buff, &op->ver, sizeof(op->ver));
		if (op->ver != 0x05) return -1;

		buff_read(buff, &op->nmethods, sizeof(op->nmethods));
		*nreaded += nheader;
	} else return 0;

methods:
	// METHODS(1-255)
	if (buff_readable(buff) >= op->nmethods) {
		buff_read(buff, op->methods, op->nmethods);

		uint8_t reply[2];
		reply[0] = 0x05; // socks5
		int auth = strcmp(SERVER.username, "") != 0 && strcmp(SERVER.passwd, "");
		if (auth) {
			reply[1] = 0x02;
			tunnel->state = auth_state;
		} else {
			reply[1] = 0x00;
			tunnel->state = request_state;
		}
		*nreaded = 0;
		return tunnel_write_client(tunnel, reply, sizeof(reply));
	} else return 0;

	return 0;
}

// |VER(1)|ULEN(1)|UNAME(1-255)|PLEN(1)|PASSWD(1-255)|
static int tunnel_auth_handle(tunnel_t* tunnel)
{
	buff_t *buff = tunnel->client_sock->read_buff;
	auth_protocol_t *ap = &tunnel->ap;
	size_t *nreaded = &tunnel->read_count;
	size_t nheader = sizeof(ap->ver) + sizeof(ap->ulen);
	size_t nplen = sizeof(ap->plen);

	if (*nreaded == 0) goto header;
	else if(*nreaded == nheader) goto uname;
	else if(*nreaded == nheader + ap->ulen) goto plen;
	else if (*nreaded == nheader + ap->ulen + nplen) goto passwd;
	else assert(0);

header:
	// VER(1)|ULEN(1)
	if (buff_readable(buff) >= nheader) {
		buff_read(buff, &ap->ver, sizeof(ap->ver));
		buff_read(buff, &ap->ulen, sizeof(ap->ulen));
		if (ap->ulen > MAX_UNAME_LEN) return -1;

		*nreaded += nheader;
	} else return 0;

uname:
	// UNAME(1-255)
	if (buff_readable(buff) >= ap->ulen) {
		buff_read(buff, ap->uname, ap->ulen);
		*nreaded += ap->ulen;
	} else return 0;

plen:
	// PLEN(1)
	if (buff_readable(buff) >= nplen) {
		buff_read(buff, &ap->plen, nplen);
		if (ap->plen > MAX_PASSWD_LEN) return -1;
		*nreaded += nplen;
	} else return 0;

passwd:
	// PASSWD(1-255)
	if (buff_readable(buff) >= ap->plen) {
		buff_read(buff, ap->passwd, ap->plen);
		if (strcmp(ap->uname, SERVER.username) != 0 || strcmp(ap->passwd, SERVER.passwd) != 0) return -1;

		uint8_t reply[2];
		reply[0] = ap->ver; // subversion
		reply[1] = 0x00; // success

		if (tunnel_write_client(tunnel, reply, sizeof(reply)) < 0) return -1;

		tunnel->state = request_state;
		*nreaded  = 0;
	} else return 0;

	return 0;
}

// |VER(1)|REP(1)|RSV(1)|ATYP(1))|BIND.ADDR(variable)|BIND.PORT(2)|
static int tunnel_notify_connected(tunnel_t *tunnel)
{
	sockaddr_t sa;
	socklen_t len = sizeof(sa);
	uint8_t header[4];
	header[0] = 0x05; // socks5
	header[1] = 0x00; // success
	header[2] = 0x00;

	if (getsockname(tunnel->remote_sock->fd, &sa, &len) < 0) return -1;

	if (sa.sa_family == AF_INET) {
		header[3] = 0x01; //IPV4
		if (tunnel_write_client(tunnel, header, sizeof(header)) < 0) return -1;

		sockaddr_in_t *sa_in = (sockaddr_in_t*)&sa;
		if (tunnel_write_client(tunnel, &sa_in->sin_addr, sizeof(sa_in->sin_addr)) < 0) return -1;
		if (tunnel_write_client(tunnel, &sa_in->sin_port, sizeof(sa_in->sin_port)) < 0) return -1;
	} else if (sa.sa_family == AF_INET6) {
		header[3] = 0x04; //IPV6
		tunnel_write_client(tunnel, header, sizeof(header));

		sockaddr_in6_t *sa_in6 = (sockaddr_in6_t*)&sa;
		tunnel_write_client(tunnel, &sa_in6->sin6_addr, sizeof(sa_in6->sin6_addr));
		tunnel_write_client(tunnel, &sa_in6->sin6_port, sizeof(sa_in6->sin6_port));
	} else {
		LOG("tunnel_notify_connected,unexpected family=%d", sa.sa_family);
		return -1;
	}

	return 0;
}

static int tunnel_connect_to_remote(tunnel_t *tunnel)
{
	uint8_t atyp = tunnel->rp.atyp;
	char *addr;
	char ip[64];
	char port[16];

	snprintf(port, sizeof(port),"%d", ntohs(tunnel->rp.port));
	switch(atyp) {
		case 0x01: // ipv4
			inet_ntop(AF_INET, tunnel->rp.addr, ip, sizeof(ip));
			addr = ip;
			break;
		case 0x04: // ipv6
			inet_ntop(AF_INET6, tunnel->rp.addr, ip, sizeof(ip));
			addr = ip;
			break;
		case 0x03: // domain
			addr = tunnel->rp.addr;
			break;
		default:
			assert(0);
			break;
	}

	addrinfo_t ai_hint;
	memset(&ai_hint, 0, sizeof(ai_hint));

	ai_hint.ai_family = AF_UNSPEC;
	ai_hint.ai_socktype = SOCK_STREAM;
	ai_hint.ai_protocol = IPPROTO_TCP;

	addrinfo_t *ai_list;
	addrinfo_t *ai_ptr;
	
	// TODO: getaddrinfo is a block function, try doing it in thread
	if (getaddrinfo(addr, port, &ai_hint, &ai_list) != 0) {
		LOG("getaddrinfo failed,addr=%s,port=%s,error=%s", addr, port, gai_strerror(errno));
		return -1;
	}

	int newfd = -1;
	int status;
	for (ai_ptr = ai_list; ai_ptr != NULL; ai_ptr = ai_ptr->ai_next) {
		newfd = socket(ai_ptr->ai_family, ai_ptr->ai_socktype, ai_ptr->ai_protocol);
		if (newfd < 0) continue;
		sock_nonblocking(newfd);
		sock_keepalive(newfd);

		if ((status = connect(newfd, ai_ptr->ai_addr, ai_ptr->ai_addrlen)) != 0 && errno != EINPROGRESS) {
			close(newfd);
			newfd = -1;
			continue;
		}

		break;
	}
	freeaddrinfo(ai_list);

	if (newfd < 0) return -1;

	sock_t *sock = sock_create(newfd, sock_connecting, 0, tunnel);
	if (sock == NULL) {
		close(newfd);
		return -1;
	}
	tunnel->remote_sock = sock;
	
	epoll_add(sock);
	epoll_modify(sock, 1, 1);

	if (status == 0) {
		tunnel->state = connected_state;
		sock->state = sock_connected;
		return tunnel_notify_connected(tunnel);
	} else {
		tunnel->state = connecting_state;
		sock->state = sock_connecting;
	}
	
	return 0;
}

// |VER(1)|CMD(1))|RSV(1)|ATYP(1)|DST.ADDR(variable)|DST.PORT(2)|
#define NIPV4 4
#define NIPV6 16

static int tunnel_request_handle(tunnel_t *tunnel)
{
	buff_t *buff = tunnel->client_sock->read_buff;
	request_protocol_t *rp = &tunnel->rp;
	size_t *nreaded = &tunnel->read_count;
	size_t nheader = sizeof(rp->ver) + sizeof(rp->cmd) + sizeof(rp->rsv) + sizeof(rp->atyp);
	size_t ndomainlen = sizeof(rp->domainlen);
	size_t nport = sizeof(rp->port);

	if (*nreaded == 0) goto header;
	else if(*nreaded == nheader) goto addr;
	else if (*nreaded == nheader + ndomainlen) goto domain;
	else assert(0);

header:
	// VER(1)|CMD(1))|RSV(1)|ATYP(1)
	if (buff_readable(buff) >= nheader) {
		buff_read(buff, &rp->ver, sizeof(rp->ver));
		if (rp->ver != 0x05) return -1;

		buff_read(buff, &rp->cmd, sizeof(rp->cmd));
		switch (rp->cmd) {
			case 0x01: // CONNECT
				break;
			case 0x02: // TODO implement BIND
			case 0x03: // TODO implement ASSOCIATE
			default:
				LOG("tunnel_request_handle,CMD not support,cmd=%d", rp->cmd);
				return -1;
		}

		buff_read(buff, &rp->rsv, sizeof(rp->rsv));
		buff_read(buff, &rp->atyp, sizeof(rp->atyp));
		*nreaded += nheader;
	} else return 0;

addr:
	switch (rp->atyp) {
		case 0x01: // IPV4
			// DST.ADDR(variable)|DST.PORT(2)
			if (buff_readable(buff) >= NIPV4 + nport) {
				buff_read(buff, rp->addr, NIPV4);
				buff_read(buff, &rp->port, nport);
			} else return 0;
			break;
		case 0x04: // IPV6
			// DST.ADDR(variable)|DST.PORT(2)
			if (buff_readable(buff) >= NIPV6 + nport) {
				buff_read(buff, rp->addr, NIPV6);
				buff_read(buff, &rp->port, nport);
			} else return 0;
			break;
		case 0x03: // DOMAIN
			{
				// DST.ADDR[0](1)
				if (buff_readable(buff) >= ndomainlen) {
					buff_read(buff, &rp->domainlen, ndomainlen);
					*nreaded += ndomainlen;
				} else return 0;

domain:
				// DST.ADDR[1](DST.ADDR[0])|DST.PORT(2)
				if (buff_readable(buff) >= rp->domainlen + nport) {
					buff_read(buff, rp->addr, rp->domainlen);
					buff_read(buff, &rp->port, nport);
				} else return 0;
			}
			break;
		default:
			return -1;
	}

	*nreaded = 0;
	return tunnel_connect_to_remote(tunnel);
}

static int tunnel_connecting_handle(tunnel_t *tunnel)
{
	int error;
	socklen_t len = sizeof(error);
	int code = getsockopt(tunnel->remote_sock->fd, SOL_SOCKET, SO_ERROR, &error, &len);
	/*
	 * If error occur, Solairs return -1 and set error to errno.
	 * Berkeley return 0 but not set errno.
	 */
	if (code < 0 || error) {
		if (error) errno = error;
		return -1;
	} 

	tunnel->state = connected_state;
	tunnel->remote_sock->state = sock_connected;
	return tunnel_notify_connected(tunnel);
}

/*
 * For data forward:
 * If client readable, append client_read_buff to remote_write_buff
 * Else, append remote_read_buff to client_write_buff
 */
static int tunnel_connected_handle(tunnel_t *tunnel, int client)
{
	if (client) {
		if (tunnel->remote_sock == NULL) return -1;

		if (buff_concat(tunnel->remote_sock->write_buff, tunnel->client_sock->read_buff) < 0) return -1;
		buff_clear(tunnel->client_sock->read_buff);
		epoll_modify(tunnel->remote_sock, 1, 1);
	} else {
		if (tunnel->client_sock == NULL) return -1;

		if (buff_concat(tunnel->client_sock->write_buff, tunnel->remote_sock->read_buff) < 0) return -1;
		buff_clear(tunnel->remote_sock->read_buff);
		epoll_modify(tunnel->client_sock, 1, 1);
	}
	return 0;
}

static int tunnel_write_client(tunnel_t *tunnel, void *src, size_t size)
{
	if (tunnel->client_sock == NULL) return -1;

	if (buff_write(tunnel->client_sock->write_buff, src, size) < 0) return -1;
	
	epoll_modify(tunnel->client_sock, 1, 1);
	return 0;
}

static void accept_handle()
{
	int newfd;
	if ((newfd = accept(SERVER.listenfd, NULL, NULL)) < 0) {
		LOG("accept_handle failed,listenfd=%d,err=%s", SERVER.listenfd, strerror(errno));
		return;
	}

	tunnel_create(newfd);
}

static void sigign()
{
	struct sigaction sa;
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGPIPE, &sa, 0);
}

static int server_start()
{
	epoll_event_t events[MAX_EPOLL_EVENTS];
	for(;;) {
		int n = epoll_wait(SERVER.epollfd, events, MAX_EPOLL_EVENTS, -1);
		if (n < 0 && errno != EINTR) {
			LOG("epoll_wait failed,error=%s", strerror(errno));
			return -1;
		}

		for (int i = 0; i < n; ++i) {
			void *cur_ud = events[i].data.ptr;
			int cur_fd = *(int*)cur_ud;
			int cur_events = events[i].events;
			if (cur_events & EPOLLIN) {
				if (cur_fd == SERVER.listenfd) {
					accept_handle();
				} else {
					tunnel_read_handle(cur_fd, cur_ud);
				}
			} else if(cur_events & EPOLLOUT) {
				tunnel_write_handle(cur_fd, cur_ud);
			} else {
				LOG("unexpected epoll events");
			}
		}
	}

	return 0;
}

static int server_init(char *host, char *port, char *username, char *passwd)
{
	addrinfo_t ai_hint;
	memset(&ai_hint, 0, sizeof(ai_hint));

	ai_hint.ai_family = AF_UNSPEC;
	ai_hint.ai_socktype = SOCK_STREAM;
	ai_hint.ai_protocol = IPPROTO_TCP;

	addrinfo_t *ai_list;
	addrinfo_t *ai_ptr;

	if (getaddrinfo(host, port, &ai_hint, &ai_list) != 0) {
		LOG("init_server,getaddrinfo failed error=%s", gai_strerror(errno));
		return -1;
	}
	
	int listenfd = -1;
	for (ai_ptr = ai_list; ai_ptr != NULL; ai_ptr = ai_ptr->ai_next) {
		listenfd = socket(ai_ptr->ai_family, ai_ptr->ai_socktype, ai_ptr->ai_protocol);
		if (listenfd < 0) continue;
		sock_nonblocking(listenfd);

		break;
	}

	if (listenfd < 0) {
		LOG("init_server,listenfd create failed errno=%s", strerror(errno));
		return -1;
	}

	int reuse = 1;
	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (void*)&reuse, sizeof(reuse));

	if (bind(listenfd, ai_ptr->ai_addr, ai_ptr->ai_addrlen)) {
		LOG("bind failed, errno=%s", strerror(errno));
		return -1;
	}
	freeaddrinfo(ai_list);

	if (listen(listenfd, BLACKLOG) != 0) {
		LOG("listen failed, errno=%s", strerror(errno));
		return -1;
	}

	int epollfd = -1;
	if ((epollfd = epoll_create(1024)) < 0) {
		LOG("epoll_create, errno=%s", strerror(errno));
		return -1;
	}

	SERVER.epollfd = epollfd;
	SERVER.listenfd = listenfd;

	epoll_event_t event;
	event.events = EPOLLIN;
	event.data.ptr = &SERVER;
	epoll_ctl(epollfd, EPOLL_CTL_ADD, listenfd, &event);

	snprintf(SERVER.username, sizeof(SERVER.username), "%s", username);
	snprintf(SERVER.passwd, sizeof(SERVER.passwd), "%s", passwd);

	return 0;
}

static void usage()
{
	fprintf(stderr,
			"Usage:\n"
			"-a : ip address\n"
			"-p : port \n"
			"-u<optional> : username\n"
			"-k<optional> : password\n"
			);
}

int main(int n, char **args)
{
	sigign();

	char option;
	char addr[64] = "";
	char port[16] = "";
	char username[255] = "";
	char passwd[255] = "";

	while((option = getopt(n, args, "a:p:u:k:")) > 0) {
		switch(option) {
			case 'a':
				strncpy(addr, optarg, sizeof(addr));
				break;
			case 'p':
				strncpy(port, optarg, sizeof(port));
				break;
			case 'u':
				strncpy(username, optarg, sizeof(username));
				break;
			case 'k':
				strncpy(passwd, optarg, sizeof(passwd));
				break;
			default:
				usage();
				break;
		}
	}

	if (strcmp(port, "") == 0 || strcmp(addr, "") == 0) {
		usage();
		return -1;
	}

	if (server_init(addr, port, username, passwd) < 0) return -1;
	if (server_start() < 0) return -1;
	
	return 0;
}

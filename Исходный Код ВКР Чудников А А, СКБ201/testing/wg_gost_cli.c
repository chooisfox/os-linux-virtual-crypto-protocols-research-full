/* testing/wg_gost_cli.c */
#include <arpa/inet.h>
#include <errno.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define GOST_PRIV_KEY_LEN 64
#define GOST_PUB_KEY_LEN  128
#define WG_GENL_NAME	  "wiregost"

#define WGDEVICE_A_IFINDEX	   1
#define WGDEVICE_A_IFNAME	   2
#define WGDEVICE_A_PRIVATE_KEY 3
#define WGDEVICE_A_PUBLIC_KEY  4
#define WGDEVICE_A_FLAGS	   5
#define WGDEVICE_A_LISTEN_PORT 6
#define WGDEVICE_A_FWMARK	   7
#define WGDEVICE_A_PEERS	   8

#define WGPEER_A_PUBLIC_KEY					   1
#define WGPEER_A_PRESHARED_KEY				   2
#define WGPEER_A_FLAGS						   3
#define WGPEER_A_ENDPOINT					   4
#define WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL 5
#define WGPEER_A_LAST_HANDSHAKE_TIME		   6
#define WGPEER_A_RX_BYTES					   7
#define WGPEER_A_TX_BYTES					   8
#define WGPEER_A_ALLOWEDIPS					   9
#define WGPEER_A_PROTOCOL_VERSION			   10

#define WGALLOWEDIP_A_FAMILY	1
#define WGALLOWEDIP_A_IPADDR	2
#define WGALLOWEDIP_A_CIDR_MASK 3
#define WGALLOWEDIP_A_FLAGS		4

#define WG_CMD_GET_DEVICE 0
#define WG_CMD_SET_DEVICE 1

struct nl_req
{
	struct nlmsghdr	  n;
	struct genlmsghdr g;
	char			  buf[8192];
};

static int nla_ok(const struct nlattr *nla, int remaining)
{
	return remaining >= (int)sizeof(*nla) && nla->nla_len >= sizeof(*nla) && nla->nla_len <= remaining;
}

static struct nlattr *nla_next(const struct nlattr *nla, int *remaining)
{
	int totlen = NLA_ALIGN(nla->nla_len);
	*remaining -= totlen;
	return (struct nlattr *)((char *)nla + totlen);
}

static int get_family_id(int sock)
{
	struct nl_req  req = {0};
	struct nlattr *na;
	int			   id = -1;

	req.n.nlmsg_len	  = NLMSG_LENGTH(GENL_HDRLEN);
	req.n.nlmsg_type  = GENL_ID_CTRL;
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.g.cmd		  = CTRL_CMD_GETFAMILY;
	req.g.version	  = 1;

	na			 = (struct nlattr *)req.buf;
	na->nla_type = CTRL_ATTR_FAMILY_NAME;
	na->nla_len	 = NLA_HDRLEN + strlen(WG_GENL_NAME) + 1;
	memcpy((char *)na + NLA_HDRLEN, WG_GENL_NAME, strlen(WG_GENL_NAME) + 1);
	req.n.nlmsg_len += NLA_ALIGN(na->nla_len);

	if (send(sock, &req, req.n.nlmsg_len, 0) < 0)
		return -1;

	int len = recv(sock, &req, sizeof(req), 0);
	if (len < 0)
		return -1;

	struct nlmsghdr *nh = (struct nlmsghdr *)&req;
	if (nh->nlmsg_type == NLMSG_ERROR)
		return -1;

	struct nlattr *head	 = (struct nlattr *)req.buf;
	int			   aflen = nh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
	struct nlattr *nla	 = head;

	while (nla_ok(nla, aflen))
	{
		if (nla->nla_type == CTRL_ATTR_FAMILY_ID)
		{
			id = *(int *)((char *)nla + NLA_HDRLEN);
			break;
		}
		nla = nla_next(nla, &aflen);
	}
	return id;
}

static void add_attr(struct nl_req *req, int type, const void *data, int len)
{
	struct nlattr *attr = (struct nlattr *)((char *)req + req->n.nlmsg_len);
	attr->nla_len		= len + NLA_HDRLEN;
	attr->nla_type		= type;
	if (len > 0)
		memcpy((char *)attr + NLA_HDRLEN, data, len);
	req->n.nlmsg_len += NLA_ALIGN(attr->nla_len);
}

static void hex_to_bytes(const char *hex, unsigned char *bytes, int len)
{
	for (int i = 0; i < len; i++)
		sscanf(hex + 2 * i, "%02hhx", &bytes[i]);
}

static void print_hex(const unsigned char *bytes, int len)
{
	for (int i = 0; i < len; i++)
		printf("%02x", bytes[i]);
	printf("\n");
}

static void gen_random_key(unsigned char *key, int len, int seed)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	srand(ts.tv_nsec + seed);

	for (int i = 0; i < len; i++)
		key[i] = rand() % 256;

	if (len > 0)
		key[0] = 0x00;
}

int cmd_init(int sock, int family_id, int argc, char **argv)
{
	struct nl_req  req = {0};
	unsigned char  priv[GOST_PRIV_KEY_LEN];
	unsigned int   ifindex = if_nametoindex(argv[2]);
	unsigned short port	   = atoi(argv[3]);

	if (ifindex == 0)
	{
		fprintf(stderr, "Interface %s not found\n", argv[2]);
		return 1;
	}

	if (strcmp(argv[4], "gen") == 0)
	{
		gen_random_key(priv, GOST_PRIV_KEY_LEN, getpid() + port);
		printf("PRIVATE: ");
		print_hex(priv, GOST_PRIV_KEY_LEN);
	}
	else
	{
		hex_to_bytes(argv[4], priv, GOST_PRIV_KEY_LEN);
	}

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len	  = NLMSG_LENGTH(GENL_HDRLEN);
	req.n.nlmsg_type  = family_id;
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.g.cmd		  = WG_CMD_SET_DEVICE;
	req.g.version	  = 1;

	add_attr(&req, WGDEVICE_A_IFINDEX, &ifindex, sizeof(ifindex));
	add_attr(&req, WGDEVICE_A_PRIVATE_KEY, priv, GOST_PRIV_KEY_LEN);
	add_attr(&req, WGDEVICE_A_LISTEN_PORT, &port, sizeof(port));

	if (send(sock, &req, req.n.nlmsg_len, 0) < 0)
	{
		perror("send SET");
		return 1;
	}

	recv(sock, &req, sizeof(req), 0);
	if (req.n.nlmsg_type == NLMSG_ERROR)
	{
		struct nlmsgerr *err = (struct nlmsgerr *)((char *)&req.n + NLMSG_HDRLEN);
		if (err->error != 0)
		{
			fprintf(stderr, "Netlink error (SET_DEVICE): %s (%d)\n", strerror(-err->error), -err->error);
			return 1;
		}
	}

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len	  = NLMSG_LENGTH(GENL_HDRLEN);
	req.n.nlmsg_type  = family_id;
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req.g.cmd		  = WG_CMD_GET_DEVICE;
	req.g.version	  = 1;
	add_attr(&req, WGDEVICE_A_IFINDEX, &ifindex, sizeof(ifindex));

	if (send(sock, &req, req.n.nlmsg_len, 0) < 0)
	{
		perror("send GET");
		return 1;
	}

	char recv_buf[16384];
	while (1)
	{
		int len = recv(sock, recv_buf, sizeof(recv_buf), 0);
		if (len < 0)
		{
			perror("recv GET");
			return 1;
		}

		struct nlmsghdr *nh = (struct nlmsghdr *)recv_buf;
		while (NLMSG_OK(nh, len))
		{
			if (nh->nlmsg_type == NLMSG_DONE)
				return 0;
			if (nh->nlmsg_type == NLMSG_ERROR)
				return 1;

			struct genlmsghdr *gh	 = NLMSG_DATA(nh);
			struct nlattr	  *nla	 = (struct nlattr *)((char *)gh + GENL_HDRLEN);
			int				   aflen = nh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);

			while (nla_ok(nla, aflen))
			{
				if (nla->nla_type == WGDEVICE_A_PUBLIC_KEY)
				{
					printf("PUBLIC: ");
					print_hex((unsigned char *)((char *)nla + NLA_HDRLEN), GOST_PUB_KEY_LEN);
					return 0;
				}
				nla = nla_next(nla, &aflen);
			}
			nh = NLMSG_NEXT(nh, len);
		}
	}
	return 0;
}

int cmd_peer(int sock, int family_id, int argc, char **argv)
{
	struct nl_req	   req	   = {0};
	unsigned int	   ifindex = if_nametoindex(argv[2]);
	unsigned char	   pub[GOST_PUB_KEY_LEN];
	struct sockaddr_in ep4 = {0};
	unsigned char	   ip4[4];
	unsigned short	   port = atoi(argv[5]);

	if (strlen(argv[3]) != GOST_PUB_KEY_LEN * 2)
	{
		fprintf(stderr, "Invalid pubkey length. Expected %d hex chars, got %lu\n", GOST_PUB_KEY_LEN * 2, strlen(argv[3]));
		return 1;
	}
	hex_to_bytes(argv[3], pub, GOST_PUB_KEY_LEN);

	inet_pton(AF_INET, argv[4], &ep4.sin_addr);
	ep4.sin_family = AF_INET;
	ep4.sin_port   = htons(port);
	inet_pton(AF_INET, argv[6], ip4);

	req.n.nlmsg_len	  = NLMSG_LENGTH(GENL_HDRLEN);
	req.n.nlmsg_type  = family_id;
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.g.cmd		  = WG_CMD_SET_DEVICE;
	req.g.version	  = 1;

	add_attr(&req, WGDEVICE_A_IFINDEX, &ifindex, sizeof(ifindex));

	struct nlattr *peers = (struct nlattr *)((char *)&req + req.n.nlmsg_len);
	peers->nla_type		 = WGDEVICE_A_PEERS | NLA_F_NESTED;
	req.n.nlmsg_len += NLA_HDRLEN;

	struct nlattr *peer0 = (struct nlattr *)((char *)&req + req.n.nlmsg_len);
	peer0->nla_type		 = 0 | NLA_F_NESTED;
	req.n.nlmsg_len += NLA_HDRLEN;

	add_attr(&req, WGPEER_A_PUBLIC_KEY, pub, GOST_PUB_KEY_LEN);
	add_attr(&req, WGPEER_A_ENDPOINT, &ep4, sizeof(ep4));

	struct nlattr *aips = (struct nlattr *)((char *)&req + req.n.nlmsg_len);
	aips->nla_type		= WGPEER_A_ALLOWEDIPS | NLA_F_NESTED;
	req.n.nlmsg_len += NLA_HDRLEN;

	struct nlattr *aip0 = (struct nlattr *)((char *)&req + req.n.nlmsg_len);
	aip0->nla_type		= 0 | NLA_F_NESTED;
	req.n.nlmsg_len += NLA_HDRLEN;

	unsigned short fam	= AF_INET;
	unsigned char  cidr = 32;
	add_attr(&req, WGALLOWEDIP_A_FAMILY, &fam, sizeof(fam));
	add_attr(&req, WGALLOWEDIP_A_IPADDR, ip4, 4);
	add_attr(&req, WGALLOWEDIP_A_CIDR_MASK, &cidr, 1);

	aip0->nla_len  = (char *)&req + req.n.nlmsg_len - (char *)aip0;
	aips->nla_len  = (char *)&req + req.n.nlmsg_len - (char *)aips;
	peer0->nla_len = (char *)&req + req.n.nlmsg_len - (char *)peer0;
	peers->nla_len = (char *)&req + req.n.nlmsg_len - (char *)peers;

	if (send(sock, &req, req.n.nlmsg_len, 0) < 0)
	{
		perror("send");
		return 1;
	}
	recv(sock, &req, sizeof(req), 0);
	if (req.n.nlmsg_type == NLMSG_ERROR)
	{
		struct nlmsgerr *err = (struct nlmsgerr *)((char *)&req.n + NLMSG_HDRLEN);
		if (err->error != 0)
		{
			fprintf(stderr, "Netlink error (SET_PEER): %s (%d)\n", strerror(-err->error), -err->error);
			return 1;
		}
	}
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2)
		return 1;
	int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
	if (sock < 0)
	{
		perror("socket");
		return 1;
	}
	int id = get_family_id(sock);
	if (id < 0)
	{
		fprintf(stderr, "Generic Netlink Family 'wiregost' not found. Is the module loaded?\n");
		return 1;
	}

	if (strcmp(argv[1], "init") == 0)
		return cmd_init(sock, id, argc, argv);
	if (strcmp(argv[1], "peer") == 0)
		return cmd_peer(sock, id, argc, argv);
	return 0;
}

#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>
#include <netlink/netlink.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <netlink/route/addr.h>
#include <errno.h>

#include <netlink_common.h>

#define BUFFER_SIZE 4096

#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

#define for_each_nlmsg(n, buf, len)					\
	for (n = (struct nlmsghdr*)buf;					\
	     NLMSG_OK(n, (uint32_t)len) && n->nlmsg_type != NLMSG_DONE;	\
	     n = NLMSG_NEXT(n, len))

#define for_each_rattr(n, buf, len)					\
	for (n = (struct rtattr*)buf; RTA_OK(n, len); n = RTA_NEXT(n, len))


static int _nl_connect(int *sock)
{
	int s;

	s = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (s == -1)
		return -1;

	*sock = s;
	return 0;
}

static void _nl_disconnect(int sock)
{
	close(sock);
}

static int _nl_request_ip_send(int sock)
{
	struct sockaddr_nl sa = {.nl_family = AF_NETLINK};
	char buf[BUFFER_SIZE];
	struct ifaddrmsg *ifa;
	struct nlmsghdr *nl;
	struct msghdr msg;
	struct iovec iov;
	int res;

	memset(&msg, 0, sizeof(msg));
	memset(buf, 0, BUFFER_SIZE);

	nl = (struct nlmsghdr*)buf;
	nl->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	nl->nlmsg_type = RTM_GETADDR;
	nl->nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;

 	iov.iov_base = nl;
	iov.iov_len = nl->nlmsg_len;

	ifa = (struct ifaddrmsg*)NLMSG_DATA(nl);
	ifa->ifa_family = AF_INET;  /* IPv4 */

	msg.msg_name = &sa;
	msg.msg_namelen = sizeof(sa);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	res = sendmsg(sock, &msg, 0);
	if (res < 0)
		return -1;

	return 0;
}

static int _nl_response_get(int sock, void *buf, size_t *len)
{
	struct iovec iov = {.iov_base = buf, .iov_len = *len};
	struct sockaddr_nl sa = {.nl_family = AF_NETLINK};
	struct msghdr msg = {
		.msg_name = &sa,
		.msg_namelen = sizeof(sa),
		.msg_iov = &iov,
		.msg_iovlen = 1
	};
	int res;

	res = recvmsg(sock, &msg, 0);
	if (res < 0)
		return -1;
	*len = res;
	return 0;
}

static int _nl_iface_addr_parse(uint32_t vid, void *buf, size_t len,
				unsigned char prefixlen, struct nl_vid_addr *addr)
{
	struct rtattr *rta = NULL;

	for_each_rattr(rta, buf, len) {
		if (rta->rta_type == IFA_LOCAL) {
			memcpy(&addr->address, RTA_DATA(rta), sizeof(addr->address));
			addr->vid = vid;
			addr->prefixlen = prefixlen;
			break;
		}
	}

	return 0;
}

static int _nl_response_addr_parse(void *buf,
				   size_t len,
				   struct nl_vid_addr *addr_list,
				   size_t *list_size)
{
	struct ifaddrmsg *iface_addr;
	struct nlmsghdr *nl = NULL;
	char ifname[IF_NAMESIZE];
	size_t num_addrs = 0;
	uint32_t vid;
	int err = 0;

	for_each_nlmsg(nl, buf, len) {
		if (nl->nlmsg_type == NLMSG_ERROR)
			return -1;

		if (nl->nlmsg_type != RTM_NEWADDR)  /* only care for addr */
			continue;

		iface_addr = (struct ifaddrmsg*)NLMSG_DATA(nl);

		if (!if_indextoname(iface_addr->ifa_index, ifname))
			return -1;

		if (sscanf(ifname, "Vlan%u", &vid) != 1)
			continue;

		if (!addr_list || *list_size == 0) {
			num_addrs++;
			continue;
		}
		if (num_addrs > *list_size)
			return -EOVERFLOW;

		err = _nl_iface_addr_parse(vid, IFA_RTA(iface_addr), IFA_PAYLOAD(nl),
					   iface_addr->ifa_prefixlen,
					   &addr_list[num_addrs++]);
		if (err)
			break;
	}

	if (num_addrs > *list_size)
		err = -EOVERFLOW;
	*list_size = num_addrs;
	if (err)
		return err;

	return nl->nlmsg_type == NLMSG_DONE? -ENODATA : 0;
}

int nl_get_ip_list(struct nl_vid_addr *addr_list, size_t *list_size)
{
	size_t buf_len = BUFFER_SIZE, batch_size = 0, num_addrs = 0;
	char buf[BUFFER_SIZE];
	int sock = 0;
	int err;

	err = _nl_connect(&sock);
	if (err)
		return err;

	err = _nl_request_ip_send(sock);
	if (err)
		goto out;

	while (1) {
		err = _nl_response_get(sock, buf, &buf_len);
		if (err)
			goto out;

		err = _nl_response_addr_parse(buf, buf_len, NULL, &batch_size);
		if (err == -ENODATA) {
			err = 0;
			break;
		}
		if (err && err != -EOVERFLOW) {
			goto out;
		}

		num_addrs += batch_size;
		if (!addr_list || *list_size == 0)
			continue;
		if (num_addrs > *list_size) {
			err = -EOVERFLOW;
			break;
		}

		err = _nl_response_addr_parse(buf, buf_len, &addr_list[num_addrs - batch_size], &batch_size);
		if (unlikely(err == -ENODATA)) {
			err = 0;
			break;
		}
		if (err)
			goto out;
	}
	if (num_addrs > *list_size)
		err = -EOVERFLOW;
	*list_size = num_addrs;
out:
	_nl_disconnect(sock);
	return err;
}

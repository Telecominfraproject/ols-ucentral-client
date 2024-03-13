#ifndef _NETLINK_COMMON
#define _NETLINK_COMMON

struct nl_vid_addr {
	uint16_t vid;
	uint16_t prefixlen;
	uint32_t address;
};

int nl_get_ip_list(struct nl_vid_addr *addr_list, size_t *list_size);

#endif

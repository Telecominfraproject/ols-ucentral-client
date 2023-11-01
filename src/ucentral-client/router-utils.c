#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <router-utils.h>
#include <search.h>

#define ZFREE(p)           \
	do {               \
		free((p)); \
		(p) = 0;   \
	} while (0)

/* It is utilites. Can be used from proto or plat. Plat could utilize own
 * applying method (do not use ucentral_router_fib_db_apply)
 */

int ucentral_router_fib_db_alloc(struct ucentral_router *db, ssize_t max)
{
	db->arr = calloc(max, sizeof(struct ucentral_router_fib_node));
	if (!db->arr)
		return -1;

	db->len = 0;
	db->max = max;
	db->sorted = true;
	return 0;
}

void ucentral_router_fib_db_free(struct ucentral_router *db)
{
	ZFREE(db->arr);
	db->len = 0;
	db->max = 0;
	db->sorted = false;
}

int ucentral_router_fib_db_copy(struct ucentral_router *src,
				struct ucentral_router *dst)
{
	int ret;

	ret = ucentral_router_fib_db_alloc(dst, src->max);
	if (ret)
		return ret;

	memcpy(&dst->arr[0], &src->arr[0], src->len * sizeof(dst->arr[0]));
	dst->len = src->len;
	dst->sorted = src->sorted;
	return 0;
}

/* This function guarantee grouping in following way:
 *  [ vrf [ prefix_len [addr ]      ]      ]     ]
 */
int ucentral_router_fib_key_cmp(const struct ucentral_router_fib_key *a,
				const struct ucentral_router_fib_key *b)
{
	if (a->prefix_len > b->prefix_len)
		return 1;

	if (a->prefix_len < b->prefix_len)
		return -1;

	if (a->prefix.s_addr > b->prefix.s_addr)
		return 1;

	if (a->prefix.s_addr < b->prefix.s_addr)
		return -1;

	return 0;
}

int ucentral_router_fib_info_cmp(const struct ucentral_router_fib_info *a,
				 const struct ucentral_router_fib_info *b)
{
	if (a->type > b->type)
		return 1;
	if (a->type < b->type)
		return -1;

	switch (a->type) {
	case UCENTRAL_ROUTE_BLACKHOLE:
		break;
	case UCENTRAL_ROUTE_UNREACHABLE:
		break;
	case UCENTRAL_ROUTE_CONNECTED:
		if (a->connected.vid > b->connected.vid)
			return 1;
		if (a->connected.vid < b->connected.vid)
			return -1;
		break;
	case UCENTRAL_ROUTE_BROADCAST:
		if (a->broadcast.vid > b->broadcast.vid)
			return 1;
		if (a->broadcast.vid < b->broadcast.vid)
			return -1;
		break;
	case UCENTRAL_ROUTE_NH:
		if (a->nh.vid > b->nh.vid)
			return 1;
		if (a->nh.vid < b->nh.vid)
			return -1;
		if (a->nh.gw.s_addr > b->nh.gw.s_addr)
			return 1;
		if (a->nh.gw.s_addr < b->nh.gw.s_addr)
			return -1;
		break;
	default:
		break;
	}

	return 0;
}

static int __fib_node_key_cmp_cb(const void *a, const void *b)
{
	const struct ucentral_router_fib_node *na = a, *nb = b;

	return ucentral_router_fib_key_cmp(&na->key, &nb->key);
}

void ucentral_router_fib_db_sort(struct ucentral_router *r)
{
	qsort(&r->arr[0], r->len, sizeof(r->arr[0]), __fib_node_key_cmp_cb);
	r->sorted = true;
}

int ucentral_router_fib_db_append(struct ucentral_router *r,
				  struct ucentral_router_fib_node *n)
{
	if (r->len == r->max)
		return -1;

	memcpy(&r->arr[r->len], n, sizeof(*n));
	r->len++;
	r->sorted = false;
	return 0;
}


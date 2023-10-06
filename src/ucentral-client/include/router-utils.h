/* Defines router types and utils for them (lookup/etc) */

#include <netinet/in.h>

struct ucentral_router_fib_key {
	/* TODO vrf */
	struct in_addr prefix;
	int prefix_len;
} key;

struct ucentral_router_fib_info { /* Destination info */
	enum {
		UCENTRAL_ROUTE_BLACKHOLE,
		UCENTRAL_ROUTE_UNREACHABLE,
		UCENTRAL_ROUTE_CONNECTED,
		UCENTRAL_ROUTE_NH,
		UCENTRAL_ROUTE_BROADCAST
	} type;
	union {
		struct {
			uint16_t vid;
			/* port is vid with single member */
		} connected;
		struct {
			uint16_t vid;
		} broadcast;
		struct {
			uint16_t vid;
			struct in_addr gw;
		} nh;
	};
};

struct ucentral_router_fib_node {
	struct ucentral_router_fib_key key;
	struct ucentral_router_fib_info info;
};

/* Its descriptor of router. Use ucentral_router_fib_db_copy to copy. */
struct ucentral_router {
	struct ucentral_router_fib_node *arr;
	ssize_t len; /* Used */
	ssize_t max; /* Allocated */
	bool sorted;
};

struct ucentral_router_fib_db_apply_args {
	/* plat whould check info to determine if node channged */
	int (*upd_cb)(const struct ucentral_router_fib_node *old,
		      int olen,
		      const struct ucentral_router_fib_node *new,
		      int nlen,
		      void *arg);
	/* prefix = new, info = new */
	int (*add_cb)(const struct ucentral_router_fib_node *new,
		      int len, void *arg);
	/* prefix = none */
	int (*del_cb)(const struct ucentral_router_fib_node *old,
		      int len, void *arg);
	void *arg;
};

int ucentral_router_fib_db_alloc(struct ucentral_router *db, ssize_t max);
void ucentral_router_fib_db_free(struct ucentral_router *db);
int ucentral_router_fib_db_copy(struct ucentral_router *src,
				struct ucentral_router *dst);
void ucentral_router_fib_db_sort(struct ucentral_router *r);
int ucentral_router_fib_db_append(struct ucentral_router *r,
				  struct ucentral_router_fib_node *n);
int ucentral_router_fib_key_cmp(const struct ucentral_router_fib_key *a,
				const struct ucentral_router_fib_key *b);
bool ucentral_router_fib_info_cmp(const struct ucentral_router_fib_info *a,
				  const struct ucentral_router_fib_info *b);

#define router_db_get(R, I) (I < (R)->len ? &(R)->arr[(I)] : NULL)

#define for_router_db_diff_CASE_UPD(DIFF) if (!(DIFF))
#define for_router_db_diff_CASE_DEL(DIFF) if ((DIFF) > 0)
#define for_router_db_diff_CASE_ADD(DIFF) if ((DIFF) < 0)
#define for_router_db_diff(NEW, OLD, INEW, IOLD, DIFF) \
	for ((INEW) = 0, (IOLD) = 0, (NEW)->sorted ? 0 : ucentral_router_fib_db_sort((NEW)), (OLD)->sorted ? 0 : ucentral_router_fib_db_sort((OLD)); \
		((IOLD) != (OLD)->len || (INEW) != (NEW)->len) && \
		(( \
		  (DIFF) = (IOLD) == (OLD)->len ? -1 : (INEW) == (NEW)->len ? 1 : ucentral_router_fib_key_cmp(&(NEW)->arr[(INEW)].key, &(OLD)->arr[(IOLD)].key) \
		  ) || 1); \
		  (DIFF) == 0 ? ++(INEW) && ++(IOLD) : 0, (DIFF) > 0 ? ++(IOLD) : 0, (DIFF) < 0 ? ++(INEW) : 0\
	)

/*
 * 		((DIFF) == 0 && ++(INEW) && ++(IOLD)) || \
 * 		((DIFF) > 0 && ++(IOLD)) || \
 * 		((DIFF) < 0 && ++(INEW)) \
 */


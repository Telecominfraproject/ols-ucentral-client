#ifndef UCENTRAL_JSON_PARSER_H
#define UCENTRAL_JSON_PARSER_H

#define _BSD_SOURCE

#include <stdint.h>
#include <libwebsockets.h>
#include <cjson/cJSON.h>

typedef void (*uc_json_parse_cb)(cJSON *, void *);
typedef void (*uc_json_parse_error_cb)(void *);

struct uc_json_parser {
	struct lejp_ctx ctx;
	uc_json_parse_cb cb;
	uc_json_parse_error_cb error_cb;
	void *data;
	cJSON *root;
	char *str;
	size_t strsz;
	int is_continue; /* prasing is on-going */
	int sp;
	cJSON *stack[LEJP_MAX_DEPTH];
	char name[LEJP_MAX_PATH];
};

void uc_json_parser_init(struct uc_json_parser *uctx, uc_json_parse_cb cb,
			 uc_json_parse_error_cb error_cb, void *data);

void uc_json_parser_uninit(struct uc_json_parser *uctx);

void uc_json_parser_feed(struct uc_json_parser *uctx, const char *in,
			 size_t len);

#endif /* UCENTRAL_JSON_PARSER_H */

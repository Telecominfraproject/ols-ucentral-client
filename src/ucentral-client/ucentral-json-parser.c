#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libwebsockets.h>

#include <cjson/cJSON.h>

#include <ucentral-json-parser.h>

#define ALEN(array) (sizeof((array)) / sizeof((array)[0]))

static signed char uc_lejp_parse(struct lejp_ctx *ctx, char reason)
{
	char *tmp;
	cJSON *cur, *parent;
	double d;
	int ret = 0;
	struct uc_json_parser *uctx = ctx->user;

	parent = uctx->stack[uctx->sp];
	cur = 0;

	switch (reason) {
	case LEJPCB_CONSTRUCTED:
		break;

	case LEJPCB_DESTRUCTED:
		goto cleanup;

	case LEJPCB_START:
		break;

	case LEJPCB_COMPLETE:
		if (uctx && uctx->cb)
			uctx->cb(uctx->root, uctx->data);
		goto cleanup;

	case LEJPCB_FAILED:
		if (uctx && uctx->error_cb)
			uctx->error_cb(uctx->data);
		goto err;

	case LEJPCB_PAIR_NAME:
		memcpy(uctx->name, ctx->path, strlen(ctx->path) + 1);
		break;

	case LEJPCB_VAL_TRUE:
		if (!(cur = cJSON_CreateTrue()))
			goto err;
		break;

	case LEJPCB_VAL_FALSE:
		if (!(cur = cJSON_CreateFalse()))
			goto err;
		break;

	case LEJPCB_VAL_NULL:
		if (!(cur = cJSON_CreateNull()))
			goto err;
		break;

	case LEJPCB_VAL_NUM_INT:
		/* fallthrough */
	case LEJPCB_VAL_NUM_FLOAT:
		/* TODO(vb) better to forward these as strings and scanf into the final
         * repr */
		d = 0;
		if (1 != sscanf(ctx->buf, "%lf", &d))
			goto err;
		if (!(cur = cJSON_CreateNumber(d)))
			goto err;
		break;

	case LEJPCB_VAL_STR_START:
		uctx->strsz = 1;
		break;

	case LEJPCB_VAL_STR_CHUNK:
		/* fallthrough */
	case LEJPCB_VAL_STR_END:
		if (!(tmp = realloc(uctx->str, uctx->strsz + ctx->npos)))
			goto err;
		uctx->str = tmp;
		memcpy(&uctx->str[uctx->strsz - 1], ctx->buf, ctx->npos);
		uctx->strsz += ctx->npos;
		if (reason == LEJPCB_VAL_STR_END) {
			uctx->str[uctx->strsz - 1] = 0;
			if (!(cur = cJSON_CreateString(uctx->str)))
				goto err;
			free(uctx->str);
			uctx->str = 0;
			uctx->strsz = 0;
		}
		break;

	case LEJPCB_ARRAY_START:
		if (!(cur = cJSON_CreateArray()))
			goto err;
		lejp_parser_push(ctx, 0, 0, 0, uc_lejp_parse);
		if ((size_t)uctx->sp + 1 >= ALEN(uctx->stack))
			goto err;
		uctx->stack[++uctx->sp] = cur;
		break;

	case LEJPCB_ARRAY_END:
		--uctx->sp;
		if (uctx->sp < 0)
			goto err;
		lejp_parser_pop(ctx);
		break;

	case LEJPCB_OBJECT_START:
		if (!(cur = cJSON_CreateObject()))
			goto err;
		lejp_parser_push(ctx, 0, 0, 0, uc_lejp_parse);
		if ((size_t)uctx->sp + 1 >= ALEN(uctx->stack))
			goto err;
		uctx->stack[++uctx->sp] = cur;
		break;

	case LEJPCB_OBJECT_END:
		--uctx->sp;
		if (uctx->sp < 0)
			goto err;
		lejp_parser_pop(ctx);
		break;

	default:
		goto err;
	}

	if (!cur)
		return 0;

	if (parent) {
		if (cJSON_IsObject(parent)) {
			cJSON_AddItemToObject(parent, uctx->name, cur);
		} else if (cJSON_IsArray(parent)) {
			cJSON_AddItemToArray(parent, cur);
		} else {
			cJSON_Delete(cur);
			goto err;
		}
	}

	if (!uctx->root)
		uctx->root = cur;

	return 0;

err:
	ret = -1;
cleanup:
	uctx->sp = 0;
	free(uctx->str);
	uctx->str = 0;
	uctx->strsz = 0;
	cJSON_Delete(uctx->root);
	uctx->root = 0;
	return ret;
}

void uc_json_parser_init(struct uc_json_parser *uctx, uc_json_parse_cb cb,
			 uc_json_parse_error_cb error_cb, void *data)
{
	*uctx = (struct uc_json_parser){
		.cb = cb,
		.error_cb = error_cb,
		.data = data,
	};
	lejp_construct(&uctx->ctx, uc_lejp_parse, uctx, 0, 0);
}

void uc_json_parser_uninit(struct uc_json_parser *uctx)
{
	lejp_destruct(&uctx->ctx);
	free(uctx->str);
	cJSON_Delete(uctx->root);
	*uctx = (struct uc_json_parser){ 0 };
}

void uc_json_parser_feed(struct uc_json_parser *uctx, const char *in,
			 size_t len)
{
	int rc;
	size_t i;

	i = 0;
	while (i < len) {
		rc = lejp_parse(&uctx->ctx, (unsigned char *)&in[i], 1);
		if (rc == LEJP_CONTINUE) {
			uctx->is_continue = 1;
			++i;
			continue;
		}

		lejp_destruct(&uctx->ctx);
		lejp_construct(&uctx->ctx, uc_lejp_parse, uctx, 0, 0);

		if (rc >= 0 || !uctx->is_continue) {
			++i;
		} else {
			/* treat the current character as a part of a new object */
		}

		uctx->is_continue = 0;
	}
}

/* TODO(vb) reduce number of headers */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#undef NDEBUG
#include <assert.h>

#include <libwebsockets.h>
#include <cjson/cJSON.h>

#include <ucentral-json-parser.h>

#define ALEN(array) (sizeof((array)) / sizeof((array)[0]))
#define STR(...) #__VA_ARGS__
#define EXPECTED(...) (const char *[]){__VA_ARGS__ __VA_OPT__(, )(0)}
#define T(STREAM, EXP, EXP_ERR)                                      \
	do {                                                             \
		fputs("INPUT(" #STREAM ") " #EXP " EXPECTED_ERROR(" #EXP_ERR ")\n",                                                 \
		      stderr);                                               \
		test_parse((STREAM), ALEN(STREAM) - 1, (EXP), (EXP_ERR));    \
	} while (0)

#define TEST_JSON_1                                       \
STR(    {                                               ) \
STR(      "elem_obj1":{                                 ) \
STR(        "elem_obj2": {                              ) \
STR(            "OK": "YES",                            ) \
STR(            "OK": "YES",                            ) \
STR(            "OK_0str": "",                          ) \
STR(            "OK_True": true,                        ) \
STR(            "OK_False": false,                      ) \
STR(            "OK_Num": 120.120,                      ) \
STR(            "OK_NumInt": 120                        ) \
STR(        },                                          ) \
STR(        "elem_obj3": {},                            ) \
STR(        "elem_arr1": [                              ) \
STR(            {                                       ) \
STR(                "name":"elem_array_0"               ) \
STR(            },                                      ) \
STR(            [                                       ) \
STR(                {                                   ) \
STR(                    "even_more_nested": 1.01,       ) \
STR(                    "even_more_nested_again": {     ) \
STR(                        "nested":1                  ) \
STR(                    },                              ) \
STR(                    "ok": []                        ) \
STR(                }                                   ) \
STR(            ],                                      ) \
STR(            "ok",                                   ) \
STR(            null,                                   ) \
STR(            true,                                   ) \
STR(            false                                   ) \
STR(        ]                                           ) \
STR(      }                                             ) \
STR(    }                                               )

#define TEST_JSON_2_INVALID \
STR(    {                            ) \
STR(      "elem_obj1":{              ) \
STR(        "elem_obj2": {           ) \
STR(            "OK": "",            ) \
STR(            "NOT_OK": null,},    ) \
STR(        "elem_obj3": {},         )
#define TEST_JSON_3_LONGSTR \
	STR(["eyondthem,abovetheinterveningwoods,rosethefour-teen-storytowerof)  \
STR(Elstead.DiminthehazyEnglishair,HindheadandSelborneinvitedtheeye)     \
STR(intoablueromanticdistance.Butitwasnotalonethedistancethathad)        \
STR(attractedtheSavagetohislighthouse;thenearwasasseductiveasthefar.)    \
STR(Thewoods,theopenstretchesofheatherandyellowgorse,theclumpsofScotch)  \
STR(firs,theshiningpondswiththeirover-hangingbirchtrees,theirwater)      \
STR(lilies,theirbedsofrushes–thesewerebeautifuland,toaneyeaccustomedto)  \
STR(thearidi-tiesoftheAmericandesert,astonishing.Andthenthesoli-tude!)   \
STR(Wholedayspassedduringwhichheneversawahumanbeing.Thelighthousewas)    \
STR(onlyaquarterofanhour’sflightfromtheCharing-TTower;butthehillsof)     \
STR(MalpaiswerehardlymoredesertedthanthisSurreyheath.Thecrowdsthatdaily) \
STR(leftLondon,leftitonlytoplayElectro-magneticGolforTennis.Puttenham)   \
STR(possessednolinks;thenearestRiemann-surfaceswereatGuildford.Flowers)  \
STR(andalandscapeweretheonlyattractionshere.Andso,astherewasnogood)      \
STR(reasonforcoming,nobodycame.DuringthefirstdaystheSavagelivedalone)    \
STR(andundisturbed."])

#define TEST_JSON_4_INCOMPLETE \
STR(    {                            ) \
STR(      "elem_obj1":{              ) \
STR(        "elem_obj2": {           ) \
STR(            "OK": "",            ) \
STR(            "INCOMPLETE_OK"      )
#define TEST_JSON_5                                    \
STR(     {                                           ) \
STR(       "ethernet": [                             ) \
STR(         {                                       ) \
STR(           "duplex": "full",                     ) \
STR(           "enabled": true,                      ) \
STR(           "select-ports": [                     ) \
STR(             "Ethernet*"                         ) \
STR(           ],                                    ) \
STR(           "speed": "1000"                       ) \
STR(         }                                       ) \
STR(       ],                                        ) \
STR(       "interfaces": [                           ) \
STR(         {                                       ) \
STR(           "ethernet": [                         ) \
STR(             {                                   ) \
STR(               "select-ports": [                 ) \
STR(                 "Ethernet*"                     ) \
STR(               ],                                ) \
STR(               "vlan-tag": "un-tagged"           ) \
STR(             }                                   ) \
STR(           ],                                    ) \
STR(           "name": "mgmt",                       ) \
STR(           "role": "upstream",                   ) \
STR(           "services": [                         ) \
STR(             "ssh",                              ) \
STR(             "lldp"                              ) \
STR(           ],                                    ) \
STR(           "vlan": {                             ) \
STR(             "id": 1,                            ) \
STR(             "proto": "802.1q"                   ) \
STR(           }                                     ) \
STR(         }                                       ) \
STR(       ],                                        ) \
STR(       "metrics": { },                           ) \
STR(       "services": {},                           ) \
STR(       "uuid": 1                                 ) \
STR(     }                                           )

struct parse_verify_ctx {
	const char **exp_json; /* 0-terminated array */
	int match_cnt;
	int error_cnt;
};

static void parse_verify_error(void *data)
{
	struct parse_verify_ctx *ctx = data;
	++ctx->error_cnt;
}

static void parse_verify(cJSON *j, void *data)
{
	char *p;
	cJSON *ej;
	struct parse_verify_ctx *ctx = data;

	if (!ctx->exp_json[ctx->match_cnt])
		return;

	p = cJSON_Print(j);
	free(p);
	ej = cJSON_Parse(ctx->exp_json[ctx->match_cnt]);
	assert(ej);

	if (cJSON_Compare(ej, j, 1))
		++ctx->match_cnt;

	cJSON_Delete(ej);
}

static void test_parse(const char *stream, size_t stream_sz,
		       const char **exp_json, int exp_err_cnt)
{
	int exp_cnt;
	struct uc_json_parser p;
	struct parse_verify_ctx v = { .exp_json = exp_json };

	for (exp_cnt = 0; exp_json[exp_cnt]; ++exp_cnt)
		;

	uc_json_parser_init(&p, parse_verify, parse_verify_error, &v);
	uc_json_parser_feed(&p, stream, stream_sz);

	/* TODO(vb) make it a single expression */
	if (v.match_cnt != exp_cnt) {
		fprintf(stderr, "match_cnt(%d) != exp_cnt(%d)\n", v.match_cnt,
			exp_cnt);
		abort();
	}

	if (exp_err_cnt >= 0) {
		if (v.error_cnt != exp_err_cnt) {
			fprintf(stderr, "v.error_cnt(%d) != exp_err_cnt(%d)\n",
				v.error_cnt, exp_err_cnt);
			abort();
		}
	}

	uc_json_parser_uninit(&p);
}

int main(void)
{
	/* TODO(vb) add adequate testcases (call with partial jsons etc) */
	/* TODO(vb)  T(STR({}), EXPECTED(STR({})), 0); fails;
     *      echo '{}' | ./build/bin/libwebsockets-test-lejp
     *      also fails; but empty arrays are good
     */
	T(STR({"": ""}), EXPECTED(STR({"":""})), 0);
	T(STR([]), EXPECTED(STR([])), 0);

	T(STR({"ok":"ok"}["ok"]), EXPECTED(STR({"ok":"ok"}), STR(["ok"])), 0);
	/* test with trash */
	T(STR(adf3_j2:{"ok":"ok"}fadsf[]), EXPECTED(STR({"ok":"ok"}), STR([])), 13);

	T(TEST_JSON_1, EXPECTED(TEST_JSON_1), 0);
	T(TEST_JSON_5, EXPECTED(TEST_JSON_5), 0);
	T(TEST_JSON_3_LONGSTR, EXPECTED(TEST_JSON_3_LONGSTR), 0);
	T(TEST_JSON_2_INVALID, EXPECTED(), 18);
	T(TEST_JSON_2_INVALID TEST_JSON_3_LONGSTR,
	  EXPECTED(TEST_JSON_3_LONGSTR), 18);

	T(TEST_JSON_3_LONGSTR TEST_JSON_4_INCOMPLETE TEST_JSON_1,
	  EXPECTED(TEST_JSON_3_LONGSTR, TEST_JSON_1), 1);

	T(TEST_JSON_3_LONGSTR TEST_JSON_4_INCOMPLETE ":" TEST_JSON_1,
	  EXPECTED(TEST_JSON_3_LONGSTR), 0);

	return 0;
}

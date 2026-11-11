// minimal JSON: parser (DOM-ish) + writer helpers
#ifndef WDTT_JSON_H
#define WDTT_JSON_H

#include "util.h"

typedef enum {
    J_NULL,
    J_BOOL,
    J_NUM,
    J_STR,
    J_ARR,
    J_OBJ
} JType;

typedef struct JVal JVal;
struct JVal {
    JType type;
    // J_BOOL / J_NUM
    double num;
    int boolean;
    // J_STR
    char *str;
    size_t strlen;
    // J_ARR / J_OBJ
    char **keys;   // OBJ only
    JVal **items;  // values
    size_t n, cap;
};

// parse; returns NULL on error
JVal *json_parse(const char *s, size_t n);
void  json_free(JVal *v);

// accessors (safe on any type)
const char *json_get_str(const JVal *obj, const char *key);     // NULL if missing/non-str
long long   json_get_int(const JVal *obj, const char *key, long long def);
int         json_get_bool(const JVal *obj, const char *key, int def);
JVal       *json_get(const JVal *obj, const char *key);
JVal       *json_idx(const JVal *arr, size_t i);

// writer: build JSON into Buf
void jsonw_str(Buf *b, const char *s);            // quoted+escaped string
void jsonw_kv_str(Buf *b, const char *k, const char *v);
void jsonw_kv_int(Buf *b, const char *k, long long v);
void jsonw_kv_bool(Buf *b, const char *k, int v);
void jsonw_kv_raw(Buf *b, const char *k, const char *raw_json);

#endif

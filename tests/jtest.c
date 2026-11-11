#include "../src/json.h"
#include "../src/util.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
int main(void){
  const char *s = "{\"a\":1,\"b\":\"x\\u00e9\\n\",\"c\":[true,null,\"m\"],\"d\":{\"e\":-2.5}}";
  JVal *v = json_parse(s, strlen(s));
  assert(v && v->type==J_OBJ);
  assert(json_get_int(v,"a",0)==1);
  const char *b = json_get_str(v,"b");
  assert(b && strcmp(b,"x\xc3\xa9\n")==0);
  JVal *c = json_get(v,"c");
  assert(c && c->n==3 && c->items[0]->type==J_BOOL && c->items[0]->boolean==1);
  assert(json_idx(c,2) && strcmp(json_idx(c,2)->str,"m")==0);
  JVal *d = json_get(v,"d");
  assert(d && d->type==J_OBJ);
  Buf w; buf_init(&w);
  jsonw_kv_str(&w,"b",b); jsonw_kv_int(&w,"n",-42); jsonw_kv_bool(&w,"f",1);
  printf("writer: %s\n", w.s);
  // reject trailing garbage
  assert(json_parse("{} x",4)==NULL);
  // deep nesting guard
  char deep[200]; memset(deep,'[',150); deep[150]=0;
  assert(json_parse(deep,150)==NULL);
  puts("JSON OK");
  return 0;
}

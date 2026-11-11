// subscription serving: /sub/<subID> (client-facing, byte-compatible format)
#ifndef WDTT_SUB_H
#define WDTT_SUB_H

#include "http.h"

// handles /sub/<subID> (path already normalized). 0 handled, -1 not a sub path
int sub_handle(const HttpReq *req, HttpRes *res, const char *path);

#endif

#ifndef _SOCIALIZE_HUB_FRONT_H_
#define _SOCIALIZE_HUB_FRONT_H_

#include "socialize/core.h"






void* front_listen_and_serve(void* varg);


int load_config();

void sntp_fn(struct mg_connection *c, int ev, void *ev_data);

void timer_sntp_fn(void *param);

void route(struct mg_connection *c, int ev, void *ev_data);


void front_handler(struct mg_connection *c, struct mg_ws_message *wm);


void handle_healtiness_probe(struct mg_connection *c, struct mg_http_message *hm);


int front_access(struct mg_connection* c, struct mg_ws_message *wm, char* command, char* data);

void front_communicate(struct mg_connection* c, struct mg_ws_message *wm, char* command, char* data);






#endif
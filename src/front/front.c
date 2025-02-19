#include   "rat-chat/ctl.h"
#include   "rat-chat/front/front.h"
#include   "rat-chat/utils.h"


struct settings s_settings = {true, 1, 57, NULL};

uint64_t s_boot_timestamp = 0; 

char* s_json_header =
    "Content-Type: application/json\r\n"
    "Cache-Control: no-cache\r\n";

struct mg_mgr mgr;

int s_sig_num = 0;


void sntp_fn(struct mg_connection *c, int ev, void *ev_data) {
  uint64_t *expiration_time = (uint64_t *) c->data;
  if (ev == MG_EV_OPEN) {
    *expiration_time = mg_millis() + 3000;  // Store expiration time in 3s
  } else if (ev == MG_EV_SNTP_TIME) {
    uint64_t t = *(uint64_t *) ev_data;
    s_boot_timestamp = t - mg_millis();
    c->is_closing = 1;
  } else if (ev == MG_EV_POLL) {
    if (mg_millis() > *expiration_time) c->is_closing = 1;
  }
}


void timer_sntp_fn(void *param) {  // SNTP timer function. Sync up time
  mg_sntp_connect(param, "udp://time.google.com:123", sntp_fn, NULL);
}






void handle_healtiness_probe(struct mg_connection *c, struct mg_http_message *hm){

    char* ticket[MAX_USER_PASS] = {0};

    char rest_buff[MAX_REST_BUFF] = {0};


    cJSON* response = cJSON_CreateObject();

    int datalen = 0;



    cJSON_AddItemToObject(response, "status", cJSON_CreateString("success"));
    cJSON_AddItemToObject(response, "data", cJSON_CreateString("fine"));

    strcpy(rest_buff, cJSON_Print(response));

    datalen = strlen(rest_buff);

    mg_http_reply(c, 200, "", rest_buff);



}




void route(struct mg_connection *c, int ev, void *ev_data) {
  
  if (ev == MG_EV_ACCEPT) {
  
    if (c->fn_data != NULL) {  
      struct mg_tls_opts opts = {0};
      opts.cert = mg_unpacked("/certs/server_cert.pem");
      opts.key = mg_unpacked("/certs/server_key.pem");
      mg_tls_init(c, &opts);
    }
  
  } else if (ev == MG_EV_HTTP_MSG) {

    struct mg_http_message *hm = (struct mg_http_message *) ev_data;

    if (mg_match(hm->uri, mg_str("/api/healthz"), NULL)) {

        handle_healtiness_probe(c, hm);

    } 
    
    printf("WS UPGRADE!!!!!\n");

    mg_ws_upgrade(c, hm, NULL);
    
    if(DEBUG_THIS == 1){

        MG_DEBUG(("%lu %.*s %.*s -> %.*s", c->id, (int) hm->method.len,
                hm->method.buf, (int) hm->uri.len, hm->uri.buf, (int) 3,
                &c->send.buf[9]));

    }

  } else if (ev == MG_EV_WS_MSG) {

    struct mg_ws_message *wm = (struct mg_ws_message *) ev_data;
    
    front_handler(c, wm);

  }
}



void* front_listen_and_serve(void* varg){

    mg_mgr_init(&mgr);

    s_settings.device_name = strdup("rat-chat");

    mg_http_listen(&mgr, HTTP_URL, route, NULL);


    mg_timer_add(&mgr, 3600 * 1000, MG_TIMER_RUN_NOW | MG_TIMER_REPEAT,
                timer_sntp_fn, &mgr);
    
    while (s_sig_num == 0) {
        mg_mgr_poll(&mgr, 50);
    }

    mg_mgr_free(&mgr);

}




void front_handler(struct mg_connection *c, struct mg_ws_message *wm){

    char ws_command[WS_MAX_COMMAND_LEN] = {0};

    char ws_data[WS_MAX_COMMAND_DATA_LEN] = {0};

    cJSON* response = cJSON_CreateObject();

    pthread_mutex_lock(&G_MTX);

    int datalen = 0;

    int initial = 0;


    int auth_chan_idx = front_authenticate(c, wm, &initial, ws_command, ws_data);

    if (auth_chan_idx < 0){

        pthread_mutex_unlock(&G_MTX);

        return;

    } 
    
    
    if (initial == 1) {

        fmt_logln(LOGFP, "connection authenticated");

        pthread_mutex_unlock(&G_MTX);

        return;

    }

    front_communicate(auth_chan_idx, ws_command, ws_data);

    pthread_mutex_unlock(&G_MTX);
    
}



int front_authenticate(struct mg_connection* c, struct mg_ws_message *wm, int* initial, char* command, char* data){


    char ws_buff[MAX_WS_BUFF] = {0};

    cJSON* response = cJSON_CreateObject();

    int datalen = 0;

    if(wm->data.len > MAX_WS_BUFF){

        printf("failed handle ws: data too big\n");
        cJSON_AddItemToObject(response, "status", cJSON_CreateString("fail"));
        cJSON_AddItemToObject(response, "data", cJSON_CreateString("null"));
        
        strcpy(ws_buff, cJSON_Print(response));

        datalen = strlen(ws_buff);

        mg_ws_send(c, ws_buff, datalen, WEBSOCKET_OP_TEXT);
        
        return -1;
    }


    cJSON* req_obj = cJSON_Parse(wm->data.buf);

    if(req_obj == NULL){

        printf("failed handle ws: data invalid\n");


        cJSON_AddItemToObject(response, "status", cJSON_CreateString("fail"));
        cJSON_AddItemToObject(response, "data", cJSON_CreateString("null"));
        
        strcpy(ws_buff, cJSON_Print(response));

        datalen = strlen(ws_buff);

        mg_ws_send(c, ws_buff, datalen, WEBSOCKET_OP_TEXT);
        
        return -2;

    }

    cJSON* ws_command = cJSON_GetObjectItemCaseSensitive(req_obj, "command");

    if(ws_command == NULL){

        printf("failed handle ws: data invalid\n");

        cJSON_AddItemToObject(response, "status", cJSON_CreateString("fail"));
        cJSON_AddItemToObject(response, "data", cJSON_CreateString("null"));
        
        strcpy(ws_buff, cJSON_Print(response));

        datalen = strlen(ws_buff);

        mg_ws_send(c, ws_buff, datalen, WEBSOCKET_OP_TEXT);
        
        return -3;

    }



    printf("command: %s\n", ws_command->valuestring);

    datalen = strlen(ws_command->valuestring);

    if(datalen > WS_MAX_COMMAND_LEN){

        printf("failed handle ws: command too long\n");

        cJSON_AddItemToObject(response, "status", cJSON_CreateString("fail"));
        cJSON_AddItemToObject(response, "data", cJSON_CreateString("null"));
        
        strcpy(ws_buff, cJSON_Print(response));

        datalen = strlen(ws_buff);

        mg_ws_send(c, ws_buff, datalen, WEBSOCKET_OP_TEXT);
        
        return -4;
    }


    cJSON* ws_data = cJSON_GetObjectItemCaseSensitive(req_obj, "data");

    if(ws_data == NULL){

        printf("failed handle ws: no data field\n");

        cJSON_AddItemToObject(response, "status", cJSON_CreateString("fail"));
        cJSON_AddItemToObject(response, "data", cJSON_CreateString("null"));
        
        strcpy(ws_buff, cJSON_Print(response));

        datalen = strlen(ws_buff);

        mg_ws_send(c, ws_buff, datalen, WEBSOCKET_OP_TEXT);
        
        return -5;

    }

    int ws_data_len = strlen(ws_data->valuestring);

    if(ws_data_len > WS_MAX_COMMAND_DATA_LEN){

        printf("failed handle ws: data len too long\n");

        cJSON_AddItemToObject(response, "status", cJSON_CreateString("fail"));
        cJSON_AddItemToObject(response, "data", cJSON_CreateString("null"));
        
        strcpy(ws_buff, cJSON_Print(response));

        datalen = strlen(ws_buff);

        mg_ws_send(c, ws_buff, datalen, WEBSOCKET_OP_TEXT);
        
        return -6;

    }

    int frontid = (int)c->id;

    char user_id[MAX_ID_LEN] = {0};


    // TODO:
    //  simple check

    int chan_idx = 0;

    if (chan_idx < 0){

        fmt_logln(LOGFP,"not registered to chan ctx, auth"); 

        int v = idpw_verify(ws_data->valuestring);

        if(v < 0){

            fmt_logln(LOGFP,"invalid idpw"); 
            printf("failed handle ws: invalid idpw\n");
            cJSON_AddItemToObject(response, "status", cJSON_CreateString("fail"));
            cJSON_AddItemToObject(response, "data", cJSON_CreateString("invalid idpw"));
            
            strcpy(ws_buff, cJSON_Print(response));

            datalen = strlen(ws_buff);

            mg_ws_send(c, ws_buff, datalen, WEBSOCKET_OP_TEXT);

            return -10;

        } else {

            fmt_logln(LOGFP, "auth success");


            fmt_logln(LOGFP, "initial auth success");

            printf("handle ws: initial auth success\n");
            cJSON_AddItemToObject(response, "status", cJSON_CreateString("success"));
            cJSON_AddItemToObject(response, "data", cJSON_CreateString("accepted"));
            
            strcpy(ws_buff, cJSON_Print(response));

            datalen = strlen(ws_buff);

            mg_ws_send(c, ws_buff, datalen, WEBSOCKET_OP_TEXT);

            *initial = 1;

        }

    }

    strcpy(command, ws_command->valuestring);

    strcpy(data, ws_data->valuestring);

    fmt_logln(LOGFP, "auth success");

    return chan_idx;


}


void front_communicate(int chan_idx, char* command, char* data){

    char ws_buff[MAX_WS_BUFF] = {0};

    cJSON* response = cJSON_CreateObject();

    int datalen = 0;

    fmt_logln(LOGFP, "incoming front communication to sock");

    int sockfd = CHAN_CTX[chan_idx].sockfd;

    if(sockfd == 0){


        fmt_logln(LOGFP, "no sock exists for communication");


        return;

    }


    fmt_logln(LOGFP, "sock exists");

    struct HUB_PACKET hp;

    
    if (strcmp(command, WS_COMMAND_ROUNDTRIP) == 0) {

        fmt_logln(LOGFP, "roundtrip");


        memset(hp.header, 0, HUB_HEADER_BYTELEN);

        memset(hp.wbuff, 0, MAX_BUFF);

        hp.ctx_type = CHAN_ISSOCK;

        strcpy(hp.id, CHAN_CTX[chan_idx].id);

        strcpy(hp.header, HUB_HEADER_SENDSOCK);

        datalen = strlen(data);

        hp.body_len = datalen;

        strncpy(hp.wbuff, data, datalen);

        hp.flag = 0;

        ctx_write_packet(&hp);

        if(hp.flag <= 0){

            fmt_logln(LOGFP, "failed to send to sock");



            return;
        } 

        fmt_logln(LOGFP, "send to sock");


    } else {

        printf("failed handle ws: no such command\n");

        
        return;

    }

    return;

}



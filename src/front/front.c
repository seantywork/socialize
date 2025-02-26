#include   "socialize/ctl.h"
#include   "socialize/front/front.h"
#include   "socialize/utils.h"


struct user USER;

struct settings s_settings = {true, 1, 57, NULL};

uint64_t s_boot_timestamp = 0; 

char* s_json_header =
    "Content-Type: application/json\r\n"
    "Cache-Control: no-cache\r\n";

struct mg_mgr mgr;

int s_sig_num = 0;


static BIO* _keygen(int bits){

    RSA *r;
    BIGNUM *bne;
    BIO *bp_public;
    BIO *bp_private;


    EVP_PKEY *pkey;


	int ret = 0;

	unsigned long e = RSA_F4;


	bne = BN_new();
	ret = BN_set_word(bne,e);
	if(ret != 1){

        goto FREE_KEYGEN;
	}

	r = RSA_new();
	ret = RSA_generate_key_ex(r, bits, bne, NULL);
	if(ret != 1){
        goto FREE_KEYGEN;
	}

    bp_private = BIO_new(BIO_s_mem());
 
	ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);
	if(ret != 1){
        goto FREE_KEYGEN;
	}

	bp_public = BIO_new(BIO_s_mem());
	ret = PEM_write_bio_RSAPublicKey(bp_public, r);
	if(ret != 1){
        bp_public = NULL;
        goto FREE_KEYGEN;
	}

    goto EXIT_KEYGEN;

FREE_KEYGEN:

    if(bp_public != NULL){

        BIO_free_all(bp_public);
    }

EXIT_KEYGEN:

    if(bp_private != NULL){

        BIO_free_all(bp_private);
    }

    if(r != NULL){

        RSA_free(r);
    }
	
    if(bne != NULL){

        BN_free(bne);
    }

    return bp_public;
}


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




int load_config(){

    char confbuff[MAX_BUFF] = {0};

    int conflen = read_file_to_buffer(confbuff, MAX_BUFF, "config.json");

    if(conflen < 0){
  
      printf("read config.json failed\n");
  
      return -1;
    }

    cJSON *conf_json_root = cJSON_Parse(confbuff);

    if (conf_json_root == NULL){

        printf("error parsing config.json\n");

        return -1;

    }

    cJSON *conf_json = cJSON_GetObjectItemCaseSensitive(conf_json_root, "users");

    if(conf_json == NULL){

        printf("no users\n");

        return -2;
    }

    int ulen = cJSON_GetArraySize(conf_json);
    
    if(ulen < 1){

        printf("ulen < 1\n");

        return -3;
    }

    for(int i = 0; i < ulen; i++){

        cJSON* user = cJSON_GetArrayItem(conf_json, i);

        cJSON* id = cJSON_GetObjectItemCaseSensitive(user, "id");

        cJSON* pw = cJSON_GetObjectItemCaseSensitive(user, "pw");

        
        strcpy(USER.name, id->valuestring);

        strcpy(USER.pass, pw->valuestring);

        printf("loaded user: %s\n", USER.name);
    }

    return 0;

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

    } else if (mg_match(hm->uri, mg_str("/front"), NULL)) {

        printf("ws upgrade init\n");

        mg_ws_upgrade(c, hm, NULL);

        printf("ws upgraded\n");

        return;

    } else {

        struct mg_http_serve_opts opts = {.root_dir = FRONT_WEB_ROOT};

        mg_http_serve_dir(c, ev_data, &opts);

    }
    
    
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

    s_settings.device_name = strdup("socialize");

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

    int datalen = 0;

    int code = front_access(c, wm, ws_command, ws_data);

    if (code < 0){

        printf("front auth failed\n");

        return;

    } else if (code < 2){

        printf("front auth success\n");

        return;

    }

    front_communicate(c, wm, ws_command, ws_data);

    
}



int front_access(struct mg_connection* c, struct mg_ws_message *wm, char* command, char* data){


    char id[MAX_ID_LEN] = {0};
    uint8_t token[MAX_PW_LEN] = {0};


    char ws_buff[MAX_WS_BUFF] = {0};

    cJSON* response = cJSON_CreateObject();

    int datalen = 0;

    printf("access handler\n");

    if(wm->data.len > MAX_WS_BUFF){

        printf("failed handle ws: data too big\n");
        cJSON_AddItemToObject(response, "status", cJSON_CreateString("failed"));
        cJSON_AddItemToObject(response, "data", cJSON_CreateString("null"));
        
        strcpy(ws_buff, cJSON_Print(response));

        datalen = strlen(ws_buff);

        mg_ws_send(c, ws_buff, datalen, WEBSOCKET_OP_TEXT);
        
        return -1;
    }


    cJSON* req_obj = cJSON_Parse(wm->data.buf);

    if(req_obj == NULL){

        printf("failed handle ws: data invalid\n");


        cJSON_AddItemToObject(response, "status", cJSON_CreateString("failed"));
        cJSON_AddItemToObject(response, "data", cJSON_CreateString("null"));
        
        strcpy(ws_buff, cJSON_Print(response));

        datalen = strlen(ws_buff);

        mg_ws_send(c, ws_buff, datalen, WEBSOCKET_OP_TEXT);
        
        return -2;

    }

    cJSON* ws_command = cJSON_GetObjectItemCaseSensitive(req_obj, "command");

    if(ws_command == NULL){

        printf("failed handle ws: data invalid\n");

        cJSON_AddItemToObject(response, "status", cJSON_CreateString("failed"));
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

        cJSON_AddItemToObject(response, "status", cJSON_CreateString("failed"));
        cJSON_AddItemToObject(response, "data", cJSON_CreateString("null"));
        
        strcpy(ws_buff, cJSON_Print(response));

        datalen = strlen(ws_buff);

        mg_ws_send(c, ws_buff, datalen, WEBSOCKET_OP_TEXT);
        
        return -4;
    }


    cJSON* ws_data = cJSON_GetObjectItemCaseSensitive(req_obj, "data");

    if(ws_data == NULL){

        printf("failed handle ws: no data field\n");

        cJSON_AddItemToObject(response, "status", cJSON_CreateString("failed"));
        cJSON_AddItemToObject(response, "data", cJSON_CreateString("null"));
        
        strcpy(ws_buff, cJSON_Print(response));

        datalen = strlen(ws_buff);

        mg_ws_send(c, ws_buff, datalen, WEBSOCKET_OP_TEXT);
        
        return -5;

    }

    int ws_data_len = strlen(ws_data->valuestring);

    if(ws_data_len > WS_MAX_COMMAND_DATA_LEN){

        printf("failed handle ws: data len too long\n");

        cJSON_AddItemToObject(response, "status", cJSON_CreateString("failed"));
        cJSON_AddItemToObject(response, "data", cJSON_CreateString("null"));
        
        strcpy(ws_buff, cJSON_Print(response));

        datalen = strlen(ws_buff);

        mg_ws_send(c, ws_buff, datalen, WEBSOCKET_OP_TEXT);
        
        return -6;

    }

    int cid = (int)c->id;

    if(USER.cid == cid){

        strcpy(command, ws_command->valuestring);

        strcpy(data, ws_data->valuestring);

        return 2;
    }

    int v = idpw_verify(ws_data->valuestring, id, token);

    if(v < 0){

        fmt_logln(LOGFP,"invalid idpw"); 
        printf("failed handle ws: invalid idpw\n");
        cJSON_AddItemToObject(response, "status", cJSON_CreateString("failed"));
        cJSON_AddItemToObject(response, "data", cJSON_CreateString("invalid idpw"));
        
        strcpy(ws_buff, cJSON_Print(response));

        datalen = strlen(ws_buff);

        mg_ws_send(c, ws_buff, datalen, WEBSOCKET_OP_TEXT);

        return -10;

    } else {

        if(v == 0){

            fmt_logln(LOGFP, "initial auth success");

            printf("handle ws: initial auth success\n");

            strcpy(USER.token, token);

            cJSON_AddItemToObject(response, "status", cJSON_CreateString("success"));
            cJSON_AddItemToObject(response, "data", cJSON_CreateString((char*)token));
            
            strcpy(ws_buff, cJSON_Print(response));
    
            datalen = strlen(ws_buff);
    
            mg_ws_send(c, ws_buff, datalen, WEBSOCKET_OP_TEXT);

            return 0;

        } else {

            fmt_logln(LOGFP, "full auth success");

            printf("handle ws: full auth success\n");
            cJSON_AddItemToObject(response, "status", cJSON_CreateString("success"));
            cJSON_AddItemToObject(response, "data", cJSON_CreateString("auth success"));
            
            strcpy(ws_buff, cJSON_Print(response));
    
            datalen = strlen(ws_buff);

            int cid = (int)c->id;

            USER.cid = cid;
            
            mg_ws_send(c, ws_buff, datalen, WEBSOCKET_OP_TEXT);

            return 1;
        }

    }


    return -100;


}


void front_communicate(struct mg_connection* c, struct mg_ws_message *wm, char* command, char* data){

    char ws_buff[MAX_WS_BUFF] = {0};

    cJSON* response = cJSON_CreateObject();

    int datalen = 0;

    int result = 0;

    fmt_logln(LOGFP, "incoming front communication");

    if (strcmp(command, WS_COMMAND_GENCERT) == 0) {

        fmt_logln(LOGFP, "gencert");

        char newcert[MAX_BUFF] = {0};

        result = gencert(newcert, data);

        if(result < 0){

            cJSON_AddItemToObject(response, "status", cJSON_CreateString("failed"));
            cJSON_AddItemToObject(response, "data", cJSON_CreateString("gencert failed"));
            
            strcpy(ws_buff, cJSON_Print(response));
    
            datalen = strlen(ws_buff);
    
            mg_ws_send(c, ws_buff, datalen, WEBSOCKET_OP_TEXT);
    

        } else {

            cJSON_AddItemToObject(response, "status", cJSON_CreateString(WS_COMMAND_GENCERT));
            cJSON_AddItemToObject(response, "data", cJSON_CreateString(newcert));
            
            strcpy(ws_buff, cJSON_Print(response));
    
            datalen = strlen(ws_buff);
    
            mg_ws_send(c, ws_buff, datalen, WEBSOCKET_OP_TEXT);
    

        }


    } else {

        printf("failed handle ws: no such command\n");

        cJSON_AddItemToObject(response, "status", cJSON_CreateString("failed"));
        cJSON_AddItemToObject(response, "data", cJSON_CreateString("no such command"));
        
        strcpy(ws_buff, cJSON_Print(response));

        datalen = strlen(ws_buff);

        mg_ws_send(c, ws_buff, datalen, WEBSOCKET_OP_TEXT);

    }

    return;

}


int gencert(char* newcert, char* cname){

    // TODO:
    //  gencert leak check

    time_t exp_ca;
    time(&exp_ca);
    exp_ca += 315360000;

    time_t exp_s;
    time(&exp_s);
    exp_s += 31536000;

    X509* x509_s = X509_new();

    EVP_PKEY* pub_key_s = EVP_PKEY_new();

    X509_NAME* ca_name = X509_NAME_new();
    X509_NAME* s_name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(ca_name, "CN" , MBSTRING_ASC, HUB_CA_NAME, -1, -1, 0);
    X509_NAME_add_entry_by_txt(s_name ,"CN" , MBSTRING_ASC, cname, -1, -1, 0);

    char subject_alt_name[MAX_ID_LEN] = {0};
    
    sprintf(subject_alt_name, "DNS: %s", cname);

    X509_EXTENSION *extension_san = NULL;
    ASN1_OCTET_STRING *subject_alt_name_ASN1 = NULL;
    subject_alt_name_ASN1 = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(subject_alt_name_ASN1, (unsigned char*) subject_alt_name, strlen(subject_alt_name));
    X509_EXTENSION_create_by_NID(&extension_san, NID_subject_alt_name, 0, subject_alt_name_ASN1);

    BIO* pubkey = _keygen(4096);

    if(pubkey == NULL){

        printf("keygen failed\n");

        return -10;
    }
    

    pub_key_s = PEM_read_bio_PUBKEY(pubkey, NULL, NULL, NULL);

    FILE* fp = fopen(HUB_CA_PRIV, "r");

    EVP_PKEY* priv_key_ca = PEM_read_PrivateKey(fp, NULL, NULL, NULL);

    fclose(fp);


    if(ASN1_INTEGER_set(X509_get_serialNumber(x509_s), 420) == 0){
        printf("asn1 set serial number fail\n");
    }


    if(X509_time_adj_ex(X509_getm_notBefore(x509_s), 0, 0, 0) == NULL){
        printf("set time fail\n");
    }

    if(X509_time_adj_ex(X509_getm_notAfter(x509_s), 0, 0, &exp_s) == NULL){
        printf("set end time fail\n");
    }

    X509_set_issuer_name(x509_s, ca_name);
    X509_set_subject_name(x509_s, s_name);

    X509_add_ext(x509_s, extension_san, -1);

    //set public key
    if(X509_set_pubkey(x509_s, pub_key_s) == 0){
        printf("set pubkey fail\n");
    }

    //sign certificate with private key
    if(X509_sign(x509_s, priv_key_ca, EVP_sha256()) == 0){
        printf("sign fail\n");
        printf("Creating certificate failed...\n");
    }

    BIO *x509_bio = BIO_new(BIO_s_mem());

    if(!PEM_write_bio_X509(x509_bio, x509_s)){

        BIO_free(x509_bio);

        printf("failed to write cert data\n");

        return -11;

    }

    unsigned char *certbuff;

    int outlen = BIO_get_mem_data(x509_bio, &certbuff);

    if (outlen < 1){
        BIO_free(x509_bio);

        printf("failed to get cert data\n");
        return -12;
    }

    strncpy(newcert, certbuff, outlen);

    BIO_free(x509_bio);

    return 0;
}



#include "sip.h"

//////////////////
// Init var
//////

char *tab_sip_request_methods[] = {
    MESSAGE_STR,
    INVITE_STR,   
    ACK_STR,
    OPTIONS_STR,
    BYE_STR, 
    PRACK_STR,
    CANCEL_STR,
    REGISTER_STR,
    INFO_STR,
    SUBSCRIBE_STR,
    NOTIFY_STR,
    PUBLISH_STR,
    REFER_STR,
    UPDATE_STR
};

char *tab_sip_header[] = {
    //main header
    FROM_STR,
    TO_STR,
    CALL_ID_STR,
    CSEQ_STR,
    VIA_STR,
    MAX_FORWARDS_STR,
    CONTENT_TYPE_STR,
    CONTENT_LENGTH_STR,
    //Other
    ACCEPT_STR,
    ACCEPT_ENCODING_STR,
    ACCEPT_LANGUAGE_STR,
    ALERT_INFO_STR,
    ALLOW_STR,
    AUTHENTICATION_INFO_STR,
    AUTHORIZATION_STR,
    CALL_INFO_STR,
    CONTACT_STR,
    CONTENT_DISPOSITION_STR,
    CONTENT_ENCODING_STR,
    CONTENT_LANGUAGE_STR,
    DATE_STR,
    ERROR_INFO_STR,
    EXPIRES_STR,
    IN_REPLY_TO_STR,
    MIN_EXPIRES_STR,
    MIME_VERSION_STR,
    ORGANIZATION_STR,
    PRIORITY_STR,
    PROXY_AUTHENTICATE_STR,
    PROXY_AUTHORIZATION_STR,
    PROXY_REQUIRE_STR,
    RECORD_ROUTE_STR,
    REPLY_TO_STR,
    REQUIRE_STR,
    RETRY_AFTER_STR,
    ROUTE_STR,
    SERVER_STR,
    SUBJECT_STR,
    SUPPORTED_STR,
    TIMESTAMP_STR,
    UNSUPPORTED_STR,
    USER_AGENT_STR,
    WARNING_STR,
    WWW_AUTHENTICATE_STR
};

//////////////////////////
// Receive SIP
//////

inline int sip_receive(socket_t *sock, char *buffer, size_t buffer_len, char **remote_ip, unsigned int *remote_port){
    int ret = -1;
    if(sock && buffer && buffer_len > 0){
        struct sockaddr_in from = { 0 };
        if((ret = do_udp_receive(sock, buffer, buffer_len, &from)) > 0){
            if(remote_ip){
								char *r_ip = inet_ntoa(from.sin_addr);
                *remote_ip = (char**)calloc(strlen(r_ip)+1, sizeof(char));
								strcpy(*remote_ip,r_ip);
            }
            if(remote_port){
                *remote_port = ntohs(from.sin_port);
            }
        }
        INFO(LOG_SCREEN,  "-----------------------------------------------------------\n"
                          "RECEIVE FROM %s:%d SIP\n%s\n"
                          "-----------------------------------------------------------", inet_ntoa(from.sin_addr), ntohs(from.sin_port), buffer);
    }
    return (int) ret;
}

int sip_scan_sock(socket_t *sock, sip_message_t **p_sip, char **remote_ip, unsigned int *remote_port){
    char buffer[2048] = { 0 };
    size_t buffer_len = sizeof(buffer);
    if(p_sip && remote_ip && remote_port){
        if(sip_receive(sock, buffer, buffer_len, remote_ip, remote_port) <= 0){
            return (int) -1;
        }
        //if(*p_sip == NULL){
            *p_sip = (sip_message_t*)calloc(1, sizeof(sip_message_t));
        //}
        return (int) sip_parser_message(*p_sip, buffer);
    }
    return (int) -1;
}

//////////////////////////
// Send SIP
//////

int sip_send_request(socket_t *sock, char* ip_remote, unsigned int port_remote, sip_message_t *p_sip){
    char *buffer = NULL;
    int ret = -1;
    if((ret = sip_message_to_string(p_sip, &buffer, true)) != -1){
        size_t buffer_len = strlen((char*)buffer);
        if(strcmp(p_sip->method, MESSAGE_STR) == 0){
            buffer_len -= 4; // remove "\r\n"
        }
        ret = do_udp_send(sock, buffer, buffer_len, ip_remote, port_remote);
        if(buffer){
            free(buffer);
        }
    }
    return (int) ret;
}

int sip_send_response(socket_t *sock, char* ip_remote, unsigned int port_remote, sip_message_t *p_sip){
    char *buffer = NULL;
    int ret = -1;
    if((ret = sip_message_to_string(p_sip, &buffer, false)) != -1){
        ret = do_udp_send(sock, buffer, strlen((char*)buffer), ip_remote, port_remote);
        if(buffer){
            free(buffer);
        }
    }
    return (int) ret;
}

/**
 * SAMPLE

char *str = {
"MESSAGE sip:442871140400@213.144.188.100:5061 SIP/2.0\r\nVia: SIP/2.0/UDP 213.144.188.10:48375;branch=z9hG4bK.09d30702;rport;alias\r\nTo: 442871140400 <sip:442871140400@213.144.188.100:5061>;tag=15684\r\nCall-ID: 1765119653@213.144.188.10\r\nCSeq: 1 MESSAGE\r\nContent-Type: text/plain\r\nMax-Forwards: 70\r\nUser-Agent: sipsak 0.9.6\r\nFrom: sip:33643844688@213.144.188.100\r\nContent-Length: 11\r\n\r\nHello World\r\n"};


char *str2 = {"MESSAGE sip:33643844688@192.168.1.101:5061 SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.1.1:34185;branch=z9hG4bK.6d1728f2;rport;alias\r\nTo: sip:33643844688@192.168.1.101:5061\r\nCall-ID: 256803578@127.0.1.1\r\nCSeq: 1 MESSAGE\r\nContent-Type: text/plain\r\nMax-Forwards: 70\r\nUser-Agent: sipsak 0.9.6\r\nFrom: sip:442871140400@127.0.0.1:6000;tag=f4e82fa\r\nContent-Length: 11\r\n\r\nHello World\r\n"};


int main(){
    char *str_response = NULL;
    char *str_request = NULL;

    init_call_id(NULL);

    sip_message_t sip = { 0 };

    sip_parser_message(&sip, str2);

    sip.status_code = 200;
    sip.reason_phrase = (char*)calloc(3,sizeof(char));
    strcpy(sip.reason_phrase, OK_STR);
    free(sip.call_id.number);
    sip.call_id.number = NULL;
    generate_call_id(&sip.call_id.number);

    sip_message_to_string(&sip, &str_request, true);
    printf("%s\n", str_request);

    sip.cseq.number++;
    sip.content_length = 0;
    sip_message_to_string(&sip, &str_response, false);
    printf("%s\n", str_response);

    destroy_sip_message(&sip);
    return 0;
}
*/


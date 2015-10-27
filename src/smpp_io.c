
#include "smpp_io.h"

#ifndef _strcpy
#define _strcpy(dst, src) \
    dst = (char*)calloc(strlen((char*)src)+1, sizeof(char)); \
    strcpy(dst, src)
#endif /*_strcpy*/

#ifndef _strncpy
#define _strncpy(dst, src, size) \
    dst = (char*)calloc(size+1, sizeof(char)); \
    memcpy(dst, src, size)
#endif /*_strncpy*/

map *map_session_smpp;//<uint(sequence_number), smpp_data_t>

///////////////////////
// SMPP Session struct
/////

void init_smpp_session_t(smpp_session_t **p_p_smpp, unsigned int command_id, void *p_msg_smpp, void *p_sm){
    if(p_p_smpp){
        smpp_session_t *p_smpp = NULL;
        if(*p_p_smpp){
            *p_p_smpp = new_smpp_session_t();
        }
        (*p_p_smpp)->p_sm = p_sm;
        (*p_p_smpp)->p_msg_smpp = p_msg_smpp;
    }
    return;
}

void free_smpp_session(void **data){
    if(data && *data){
        smpp_session_t *p_smpp = (smpp_session_t*)*data;
        free(p_smpp->p_msg_smpp);
        //p_sm is free but not here
        free(*data);
        *data = NULL;
    }
    return;
}

///////////////////////
// SMPP Socket struct
//////

map  *cfg_smpp; // <str, config_smpp_t>

inline void destroy_config_client_smpp(config_client_smpp_t *c_smpp){
    if(c_smpp->name)
        free(c_smpp->name);
    //c_smpp->name  = NULL;
    //c_smpp->model = MODE_CLIENT;
    if(c_smpp->ip)
        free(c_smpp->ip);
    //c_smpp->ip = NULL;
    //c_smpp->port = 0;
    if(c_smpp->system_id)
        free(c_smpp->system_id);
    //c_smpp->system_id = NULL;
    if(c_smpp->password)
        free(c_smpp->password);
    //c_smpp->password = NULL;
    //c_smpp->ton = 0;
    //c_smpp->npi = 0;
    if(c_smpp->address_range)
        free(c_smpp->address_range);
    if(c_smpp->routing_to)
        free(c_smpp->routing_to);
    //c_smpp->routing_to = NULL;
    memset(c_smpp, 0, sizeof(config_client_smpp_t));
    return;
}

inline void destroy_config_smpp(config_smpp_t *smpp){
    if(smpp->name)
        free(smpp->name);
    //smpp->name  = NULL;
    //smpp->model = MODEL_CLIENT;
    if(smpp->ip)
        free(smpp->ip);
    //smpp->ip = NULL;
    //smpp->port = 0;
    if(smpp->system_id)
        free(smpp->system_id);
    //smpp->system_id = NULL;
    if(smpp->password)
        free(smpp->password);
    //smpp->password = NULL;
    //smpp->npi_src = 0;
    //smpp->ton_src = 0;
    //smpp->npi_dst = 0;
    //smpp->npi_dst = 0;
    if(smpp->system_type)
        free(smpp->system_type);
    if(smpp->service_type)
        free(smpp->service_type);
    //smpp->system_type = NULL;
    //smpp->cillabd_id = 0;
    if(smpp->routing_to)
        free(smpp->routing_to);
    //smpp->routing_to = NULL;
    if(smpp->list_c_smpp)
        map_destroy(&smpp->list_c_smpp);
    memset(smpp, 0, sizeof(config_smpp_t));
    return;
}

void free_config_client_smpp(void **c_smpp){
    destroy_config_client_smpp((config_client_smpp_t*)*c_smpp);
    free(*c_smpp);
    *c_smpp = NULL;
    return;
}

void free_config_smpp(void **smpp){
    destroy_config_smpp((config_smpp_t*)*smpp);
    free(*smpp);
    *smpp = NULL;
    return;
}

int compare_config_client_smpp(const void *c_smpp1, const void *c_smpp2){
    config_client_smpp_t *s1 = (config_client_smpp_t*)c_smpp1;
    config_client_smpp_t *s2 = (config_client_smpp_t*)c_smpp2;
    return (int) strcmp(s1->name, s2->name);
}

int compare_config_smpp(const void *smpp1, const void *smpp2){
    config_smpp_t *s1 = (config_smpp_t*)smpp1;
    config_smpp_t *s2 = (config_smpp_t*)smpp2;
    return (int) strcmp(s1->name, s2->name);
}

inline void display_config_client_smpp(config_client_smpp_t *c_smpp){
    if(c_smpp){
        char buffer[2048] = { 0 };
        sprintf(buffer, "[%s]\n"
                        STR_IP"         : %s\n"
                        STR_PORT"       : %d\n"
                        STR_SYSTEM_ID"  : %s\n"
                        STR_PASSWORD"   : %s\n"
                        STR_ROUTING_TO" : %s\n",
                c_smpp->name,
                c_smpp->ip,
                c_smpp->port,
                c_smpp->system_id,
                c_smpp->password,
                c_smpp->routing_to);
        DEBUG(LOG_SCREEN, "\n%s", buffer)
    }
    return;
}

inline void display_config_smpp(config_smpp_t *smpp){
    if(smpp){
        char buffer[2048] = { 0 };
        sprintf(buffer, "[%s]\n"
                        STR_MODEL"         : %s\n"
                        STR_IP"            : %s\n"
                        STR_PORT"          : %d\n"
                        STR_SYSTEM_ID"     : %s\n"
                        STR_PASSWORD"      : %s\n"
                        STR_NPI" : %s\n"
                        STR_TON"           : %s\n"
                        STR_SYSTEM_TYPE"   : %s\n"
                        STR_BIND"          : %s\n"
                        STR_ADDRESS_RANGE" : %s\n"
                        STR_ROUTING_TO"    : %s\n",
                smpp->name,
                str_model[smpp->model],
                smpp->ip,
                smpp->port,
                smpp->system_id,
                smpp->password,
                npi_to_str(smpp->npi),
                ton_to_str(smpp->ton),
                smpp->system_type,
                bind_to_str(smpp->command_id),
                smpp->address_range != NULL ? smpp->address_range : "",
                smpp->routing_to);
        DEBUG(LOG_SCREEN, "\n%s", buffer)
        if(smpp->list_c_smpp){
            //list clients
            iterator_map *p_it = smpp->list_c_smpp->begin;
            while(p_it){
                display_config_client_smpp((config_client_smpp_t*)p_it->value);
                p_it = p_it->next;
            }
        }
    }
    return;
}

//////////////////////////

int smpp_start_connection(config_smpp_t *p_config_smpp){
    int ret = 0;
    if(p_config_smpp != NULL && p_config_smpp->command_id > 0 && p_config_smpp->status == SMPP_DISCONNECT ){
        unsigned int *sequence_number = new_uint32();
        if(!p_config_smpp->sock){
            p_config_smpp->sock = new_socket();
        }
        if(smpp_send_bind_client(p_config_smpp->sock, p_config_smpp->command_id, p_config_smpp->ip, p_config_smpp->port, p_config_smpp->system_id, p_config_smpp->password, p_config_smpp->system_type, p_config_smpp->ton, p_config_smpp->npi, p_config_smpp->address_range, sequence_number) != -1){
            //create session
            smpp_session_t *p_session = new_smpp_session_t();
            map_set(map_session_smpp, sequence_number, p_session);
            p_config_smpp->status = SMPP_CONNECT;
            INFO(LOG_SCREEN | LOG_FILE, "Wait SMPP connection of %s:%d", p_config_smpp->ip, p_config_smpp->port)
            return (int) 0;
        }else{
            free(sequence_number);
            ERROR(LOG_SCREEN | LOG_FILE, "SMPP BIND Failed");
            return (int) -1;
        }
    }
    ERROR(LOG_SCREEN | LOG_FILE, "SMPP connection failed");
    return (int) -1;
}

int smpp_end_connection(config_smpp_t *p_config_smpp){
    if(p_config_smpp && p_config_smpp->status == SMPP_CONNECT && p_config_smpp->sock){
//        int sequence_number = 0;
//        smpp_send_unbind(p_config_smpp->sock, &sequence_number);
        tcp_close(p_config_smpp->sock);
        p_config_smpp->status = SMPP_DISCONNECT;
        free(p_config_smpp->sock);
        p_config_smpp->sock = NULL;
        return (int) 0;
    }
    INFO(LOG_SCREEN | LOG_FILE,"smpp already disconnect")
    return (int) -1;
}

int smpp_restart_connection(config_smpp_t *p_config_smpp){
    int ret = smpp_end_connection(p_config_smpp->sock);
    return (int) (ret == -1 ? -1 : smpp_start_connection(p_config_smpp->sock));
}

////////////////////////////
// SMPP PROCESSING
/////

map *map_sar_msg = NULL; 

#define search_tlv(tlv, value) \
	while(tlv && tlv->tag != value){ \
		tlv = tlv->next; \
	}

#define copy_sms(sms_in,sms_in_length,data_coding_in,sms_out) \
	{ \
		char *msg_out = NULL; \
                uint8_t ret   = 0; \
		if(strcmp(data_coding_in, "none") != 0){ \
			if((ret = conv_char_codec_str(sms_in, (size_t)sms_in_length, data_coding_in, &msg_out, (size_t)sms_in_length, cfg_main->system_charset)) == -1){ \
				if(ret = E2BIG){ \
				    WARNING(LOG_SCREEN, "Converting coding SMS is failed because the buffer is too short") \
				}else{ \
				    WARNING(LOG_SCREEN, "Converting coding SMS is failed") \
				} \
			} \
			sms_out = msg_out; \
		}else{ \
			_strncpy(sms_out, sms_in, sms_in_length); \
		} \
	}

#define smpp_get_sms(type, data, data_coding, src, dst, msg)\
    { \
        type *smt = (type*)data; \
        tlv_t *tlv = smt->tlv; \
        size_t size = strlen((char*)smt->source_addr); \
        _strncpy(src, smt->source_addr, size); \
        size = strlen((char*)smt->destination_addr); \
        _strncpy(dst, smt->destination_addr, size); \
        if(smt->short_message && smt->sm_length > 0){ \
            /*The reference number for a particular concatenated short message.*/ \
            search_tlv(tlv, TLVID_sar_msg_ref_num) \
            if(tlv && tlv->tag == TLVID_sar_msg_ref_num){ \
                char    **sar_msg   = NULL; \
                uint16_t *ref_num   = 0; \
                uint16_t  total_seg = 0; \
                int i = 0; \
                iterator_map *p_it = map_find(map_sar_msg, &(tlv->value.val16)); \
                if(p_it){ \
                    ref_num = (uint16_t*)p_it->key; \
                    sar_msg = (char**)p_it->value; \
                }else{ \
                    ref_num = new_uint16(); \
                    *ref_num = (uint16_t)tlv->value.val16; \
                } \
                 \
                /*Indicates the total number of short messages within the concatenated short message*/ \
                tlv = smt->tlv; \
                search_tlv(tlv, TLVID_sar_total_segments) \
                if(tlv && tlv->tag == TLVID_sar_total_segments){ \
                    total_seg = tlv->value.val08; \
                    if(sar_msg == NULL){ \
                        sar_msg = calloc(total_seg+1, sizeof(char*)); \
                    } \
                }else{ \
                    WARNING(LOG_SCREEN | LOG_FILE, "TLVID_sar_total_segments missing") \
                } \
     \
                /*Indicates the sequence number of a particular short message fragment within the concatenated short message*/ \
                tlv = smt->tlv; \
                search_tlv(tlv, TLVID_sar_segment_seqnum) \
                if(sar_msg && tlv && tlv->tag == TLVID_sar_segment_seqnum){ \
                    if(sar_msg[tlv->value.val08 - 1] == NULL){ \
                        copy_sms(smt->short_message,smt->sm_length,data_coding[smt->data_coding],sar_msg[tlv->value.val08-1]) \
                    } \
                    while(sar_msg[i]){ i++; } \
                }else{ \
                    WARNING(LOG_SCREEN | LOG_FILE, "TLVID_sar_segment_seqnum missing") \
                } \
     \
                if(total_seg == i){ \
                    if(implode(sar_msg, "", &msg) != 0){ \
                        ERROR(LOG_SCREEN,"Implode msg failed") \
                    } \
                    map_erase(map_sar_msg, ref_num); \
                }else{ \
                    if(p_it == NULL){ \
                        map_set(map_sar_msg, ref_num, sar_msg); \
                    } \
                    smpp_send_response(sock, req->command_id | GENERIC_NACK, ESME_ROK, &req->sequence_number); \
                } \
            }else{ \
                search_tlv(tlv, TLVID_message_payload) \
                if(tlv && tlv->tag == TLVID_message_payload && tlv->length > 0){ \
                    copy_sms(tlv->value.octet,tlv->length,data_coding[smt->data_coding],msg) \
                }else{ \
                    copy_sms(smt->short_message,smt->sm_length,data_coding[smt->data_coding],msg) \
                } \
            } \
        }else{ \
            WARNING(LOG_SCREEN | LOG_FILE, "Short message empty") \
        } \
    }

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static const char bcd_num_digits[] = {
    '0', '1', '2', '3', '4', '5', '6', '7', 
    '8', '9', '*', '#', 'a', 'b', 'c', '\0'
};

/* decode a 'called/calling/connect party BCD number' as in 10.5.4.7 */
int decode_bcd_number(char *output, int output_len, const u_int8_t *bcd_lv,  int len)
{
    int i;

    for (i = 0; i < len; i++) {
        /* lower nibble */
        output_len--;
        if (output_len < 0)
            break;
        *output++ = bcd_num_digits[bcd_lv[i] & 0xf];

        /* higher nibble */
        output_len--;
        if (output_len < 0)
            break;
        *output++ = bcd_num_digits[bcd_lv[i] >> 4];
    }
    if (output_len > 0)
        *output++ = '\0';

    return 0;
}

/* convert a single ASCII character to call-control BCD */
static int asc_to_bcd(const char asc) 
{
    int i;

    for (i = 0; i < ARRAY_SIZE(bcd_num_digits); i++) {
        if (bcd_num_digits[i] == asc)
            return i;
    }
    return -EINVAL;
}

/* convert a ASCII phone number to 'called/calling/connect party BCD number' */
int encode_bcd_number(u_int8_t *bcd_lv, u_int8_t max_len,
		      int h_len, const char *input)
{
    int in_len = strlen(input);
    int i;
    u_int8_t *bcd_cur = bcd_lv + 1 + h_len;

    /* two digits per byte, plus type byte */
    bcd_lv[0] = in_len/2 + h_len;
    if (in_len % 2)
        bcd_lv[0]++;

    if (bcd_lv[0] > max_len)
        return -EIO;

    for (i = 0; i < in_len; i++) {
        int rc = asc_to_bcd(input[i]);
        if (rc < 0)
            return rc;
        if (i % 2 == 0)
            *bcd_cur = rc;	
        else
            *bcd_cur++ |= (rc << 4);
    }
    /* append padding nibble in case of odd length */
    if (i % 2)
        *bcd_cur++ |= 0xf0;

    /* return how many bytes we used */
    return (bcd_cur - bcd_lv);
}

void bin_to_strhex(unsigned char *bin, unsigned int binsz, char **result)
{
  char          hex_str[]= "0123456789abcdef";
  unsigned int  i;

  *result = (char *)malloc(binsz * 2 + 1);
  (*result)[binsz * 2] = 0;

  if (!binsz)
    return;

  for (i = 0; i < binsz; i++)
    {
      (*result)[i * 2 + 0] = hex_str[(bin[i] >> 4) & 0x0F];
      (*result)[i * 2 + 1] = hex_str[(bin[i]     ) & 0x0F];
    }  
}

void print_hex_memory(void *mem, unsigned len) {
  int i;
  unsigned char *p = (unsigned char *)mem;
  printf("[");
  for (i=0;i<len;i++) {
    printf("0x%02x ", p[i]);
  }
  printf("]\n");
}


/* 7bit to octet packing */
int gsm_septets2octets(uint8_t *result, const uint8_t *rdata, uint8_t septet_len, uint8_t padding)
{
	int i = 0, z = 0;
	uint8_t cb, nb;
	int shift = 0;
	uint8_t *data = calloc(septet_len + 1, sizeof(uint8_t));

	if (padding) {
		shift = 7 - padding;
		/* the first zero is needed for padding */
		memcpy(data + 1, rdata, septet_len);
		septet_len++;
	} else
		memcpy(data, rdata, septet_len);

	for (i = 0; i < septet_len; i++) {
		if (shift == 7) {
			/*
			 * special end case with the. This is necessary if the
			 * last septet fits into the previous octet. E.g. 48
			 * non-extension characters:
			 *   ....ag ( a = 1100001, g = 1100111)
			 * result[40] = 100001 XX, result[41] = 1100111 1 */
			if (i + 1 < septet_len) {
				shift = 0;
				continue;
			} else if (i + 1 == septet_len)
				break;
		}

		cb = (data[i] & 0x7f) >> shift;
		if (i + 1 < septet_len) {
			nb = (data[i + 1] & 0x7f) << (7 - shift);
			cb = cb | nb;
		}

		result[z++] = cb;
		shift++;
	}

	free(data);

	return z;
}

void smpp_sms_parse(void *data, sm_data_t *p_sm)
{
    //RP-DA TLV max len 11 octets
    //RP-0A TLV max len 11 octets
    //RP-user-data (TPDU) TLV max len 234 octets
    char *msg_hex;
    struct deliver_sm_t *smt = (struct deliver_sm_t*)data;
    int offset = 0;
    static u_int8_t tp_mr = 0;
    unsigned char rp_data[234];
    //smsc
    unsigned char rp_da[11] = {0x84, 0x07, 0x91, 0x52, 0x75, 0x89, 0x00, 0x00, 0x10};
    int rp_da_len = 9;
    unsigned char rp_oa[11]; 
    int rp_oa_len = 0;
    int tp_da_len = 0;
    int tp_da_len_oct = 0;
    int tp_da_last_oct_offset = 0;
    int msg_offset = 0;
    unsigned char* msg;

    size_t size = strlen((char*)smt->source_addr);
    _strncpy(p_sm->src, smt->source_addr, size);
    size = strlen((char*)smt->destination_addr);
    _strncpy(p_sm->dst, smt->destination_addr, size);

    //**** RP-DA ****
    printf("RP-DA : T:[0x%02X] L:[0x%02X] V:", rp_da[0], rp_da[1]);
    print_hex_memory(rp_da + 2, rp_da[1]);
    //**********************

    //**** RP-OA ****
    rp_oa_len = encode_bcd_number((u_int8_t *)rp_oa + 2, 9, 0, (const char*)p_sm->src);
    rp_oa[0] = 0x82;
    rp_oa[1] = rp_oa_len;
    rp_oa[2] = 0x91; // international number
    printf("RP-OA : T:[0x%02X] L:[0x%02X] V:", rp_oa[0], rp_oa[1]);
    print_hex_memory(rp_oa + 2, rp_oa[1]);
    //**********************

    //***RP_DATA***
    
    //**** RP data type ****
    rp_data[offset] = 0x04; // RP data type  0x04
    printf("RP-DATA : T:[0x%02X] \n", rp_data[offset]);
    offset += 1;
    //**********************

    //**** RP data len ****
    offset += 1; // RP data length
    //**********************

    printf("RP-DATA : V:[start]\n");

    //**** TPDU first octet ****
    int udhi = 0;
    if (smt->esm_class & 0x40) {
        rp_data[offset] = 0x71; // set UDHI = 1
        udhi = 1;
    } else {
        rp_data[offset] = 0x31; // set UDHI = 0
    }
    printf("TPDU : First octet : [0x%02X] \n", rp_data[offset]);
    offset += 1;
    //**********************
    
    //**** TPDU TP-MR ****
    rp_data[offset] = tp_mr; // TP-MR
    printf("TPDU : TP-MR : [0x%02X] \n", rp_data[3]);
    tp_mr++;
    if (tp_mr > 0xff) {
        tp_mr = 0;
    }
    offset += 1;
    //**********************
    
    //**** TPDU TP-DA ****
    tp_da_len_oct = encode_bcd_number((u_int8_t *)rp_data + offset + 1, 9, 0, (const char*)p_sm->dst) - 1;
    tp_da_last_oct_offset = offset + 2 + tp_da_len_oct - 1;
    tp_da_len = tp_da_len_oct * 2;
    if ((rp_data[tp_da_last_oct_offset] & 0xf0) == 0xf0)
    {
        tp_da_len -= 1;
    }
    rp_data[offset] = tp_da_len; //TP-DA length - number of digits
    printf("TPDU : TP-DA : LEN : [0x%02X] \n", rp_data[offset]);
    offset += 1;
    
    rp_data[offset] = 0x91; //TP-DA type: international number
    printf("TPDU : TP-DA : TYPE : [0x%02X] \n", rp_data[offset]);
    offset += 1;
    
    printf("TPDU : TP-DA : NUMBER : ");
    print_hex_memory(rp_data + offset, tp_da_len_oct);
    offset += tp_da_len_oct;
    printf("#### tp_da_len_oct = %d \n", tp_da_len_oct);
    printf("#### tp_da_last_oct_offset = %d \n", tp_da_last_oct_offset);
    printf("#### rp_data[tp_da_last_oct_offset] = %d \n", rp_data[tp_da_last_oct_offset]);
    //**********************
    
    //**** TPDU TP-PID ****
    rp_data[offset] = 0x00;
    printf("TPDU : TP-PID : [0x%02X] \n", rp_data[offset]);
    offset += 1;
    //**********************

    //**** TPDU TP-DSC ****
    rp_data[offset] = 0x00;
    printf("TPDU : TP-DSC : [0x%02X] \n", rp_data[offset]);
    offset += 1;
    //**********************

    //**** TPDU TP-VP ****
    rp_data[offset] = 0xff;
    printf("TPDU : TP-DSC : [0x%02X] \n", rp_data[offset]);
    offset += 1;
    //**********************

    //**** TPDU TP-User-data ****
    int tp_user_data_len = 0;
    //int udh_len = 0;
    /*
    if (udhi) {
         udh_len = *smt->short_message;
         printf("TPDU : TP-User-data: UDH Len: %d", udh_len);
         memcpy(rp_data + offset, smt->short_message, udh_len + 1);
         printf("TPDU : TP-User-data: UDH : ");
         print_hex_memory(rp_data + offset, udh_len + 1);
         offset += udh_len + 1;
         
         tp_user_data_len = gsm_septets2octets(rp_data + offset + 1, smt->short_message, smt->sm_length, 0);

         
    } else {
    */
    tp_user_data_len = gsm_septets2octets(rp_data + offset + 1, smt->short_message, smt->sm_length, 0);
    rp_data[offset] = smt->sm_length; //TP-User-data-len
    printf("TPDU : TP-User-data : Len : [0x%02X] \n", rp_data[offset]);
    offset += 1;
    printf("TPDU : TP-User-data : Data : ");
    print_hex_memory(rp_data + offset, tp_user_data_len);
    offset += tp_user_data_len;
    //**********************

    printf("RP-DATA : V : [end] \n");

    //**** RP data len ****
    rp_data[1] = offset - 2; // RP data length
    printf("TPDU : RP-DATA : L : [0x%02X] \n", rp_data[1]);
    //**********************
    
    
    //copy to msg
    int msg_len = rp_da_len + rp_oa_len + 2 + offset;
    printf("#### rp_da_len = %d \n", rp_da_len);
    printf("#### rp_oa_len = %d \n", rp_oa_len);
    printf("#### offset = %d \n", offset);
    printf("#### msg_len = %d \n", msg_len);

    msg = (unsigned char*)malloc(msg_len);
    memcpy(msg, rp_da, rp_da_len);
    msg_offset += rp_da_len;
    memcpy(msg + msg_offset, rp_oa, rp_oa_len + 2);
    msg_offset += (rp_oa_len + 2);
    memcpy(msg + msg_offset, rp_data, offset);
    
    bin_to_strhex(msg, msg_len, &msg_hex);
    p_sm->msg = (unsigned char*)malloc(msg_len * 2);
    memcpy(p_sm->msg, (unsigned char*)msg_hex, msg_len * 2);
    p_sm->msg_len = msg_len * 2;
    free(msg);
    free(msg_hex);
}


int smpp_recv_processing_request_sm(socket_t *sock, char *interface, char *data_coding[16], char *ip_remote, unsigned int port_remote, void *data){
    //sent SM to Ronting function
    int ret = -1;
    if(sock && interface && ip_remote && data){
        sm_data_t *p_sm = new_sm_data_t();
        generic_nack_t *req = (generic_nack_t*)data;
        switch(req->command_id){
            case DELIVER_SM : //client
                //smpp_get_sms(deliver_sm_t, data, data_coding, p_sm->src, p_sm->dst, p_sm->msg)
                smpp_sms_parse(data, p_sm);
                INFO(LOG_SCREEN, "msg = %s | src = %s | dst = %s|",p_sm->msg, p_sm->src, p_sm->dst)
                break;
            case SUBMIT_SM : //server
                smpp_get_sms(submit_sm_t, data, data_coding, p_sm->src, p_sm->dst, p_sm->msg)
                break;
            case SUBMIT_MULTI :
                smpp_send_response(sock, req->command_id & GENERIC_NACK, ESME_RINVCMDID, req->sequence_number);
                INFO(LOG_SCREEN, "SUBMIT_MULTI not allowed")
                break;
            default :
                smpp_send_response(sock, req->command_id & GENERIC_NACK, ESME_RINVCMDID, req->sequence_number);
                INFO(LOG_SCREEN, "Data parameter is not a SMS")
                break;
        }
        if(interface && ip_remote && port_remote && p_sm->src && p_sm->dst && p_sm->msg){
            //création de sm_data_t + sauvegarde de la session SMPP
            init_sm_data_t(p_sm, sock, 0, I_SMPP, ip_remote, port_remote, data, NULL, NULL, NULL);
            p_sm->id = db_insert_sm("", req->sequence_number, interface, ip_remote, port_remote, p_sm->src, p_sm->dst, p_sm->msg);
            //save SMPP session
            unsigned int *k_smpp_data = new_uint32();//Key
            smpp_session_t *p_smpp = new_smpp_session_t();//Value
            init_smpp_session_t(&p_smpp, req->command_id, data, p_sm);
            *k_smpp_data = req->sequence_number;
            map_set(map_session_smpp, k_smpp_data, p_smpp);
            //routing
            ERROR(LOG_SCREEN | LOG_FILE, "interface = %s, ip_remote =%s, port_remote=%d",interface, ip_remote, port_remote)
            if(f_routing(interface, ip_remote, port_remote, p_sm) == -1){
                //send resp error
                ERROR(LOG_SCREEN | LOG_FILE, "Routing return -1 -> destroy SM/Session SMPP and sent error")
                smpp_send_response(sock, req->command_id + GENERIC_NACK, ESME_RINVCMDID, &req->sequence_number);
                //SMS DESTROY
                map_erase(map_session_smpp, k_smpp_data);
                free_sm_data(&p_sm);
            }
        }else{
            free_sm_data((void**)&p_sm);
        }
    }
    return (int) ret;
}

int smpp_recv_processing_request(socket_t *sock, const void *req){
    //Action sent by server | The client receive those actions
    int ret = -1;
    if(req){
        switch(((generic_nack_t*)req)->command_id){
            case UNBIND :
            {   unbind_t *unbind = (unbind_t*)req;
		ret = smpp_send_unbind_resp(sock, unbind->sequence_number, ESME_ROK);
                //TODO : clean socket, ...
            }   break;
            case ENQUIRE_LINK :
            {   enquire_link_t *enq_l = (enquire_link_t*)req;
		ret = smpp_send_unquire_link_resp(sock, enq_l->sequence_number, ESME_ROK);
            }   break;
            case QUERY_SM :
            {   //TODO
                query_sm_t *query = (query_sm_t*)req;
                ret = smpp_send_response(sock, QUERY_SM_RESP, ESME_RINVCMDID, &query->sequence_number);
                INFO(LOG_SCREEN, "QUERY_SM not allowed")
            }   break;
            case REPLACE_SM :
            {   //TODO
                replace_sm_t *repl = (replace_sm_t*)req;
		ret = smpp_send_replace_sm_resp(sock, repl->sequence_number, ESME_RINVCMDID);
                INFO(LOG_SCREEN, "REPLACE_SM not allowed")
            }   break;
            case CANCEL_SM :
            {   //TODO
                cancel_sm_t *cancel = (cancel_sm_t*)req;
		ret = smpp_send_cancel_sm_resp(sock, cancel->sequence_number, ESME_RINVCMDID);
                INFO(LOG_SCREEN, "CANCEL_SM not allowed")
            }   break;
            case ALERT_NOTIFICATION :
            {   //TODO
                alert_notification_t *alert = (alert_notification_t*)req;
                INFO(LOG_SCREEN, "ALERT_NOTIFICATION not allowed")
            }   break;
            case BIND_TRANSMITTER :
            {   bind_transmitter_t *p_bind = (bind_transmitter_t*)req;
                smpp_send_bind_receiver_resp(sock, p_bind->system_id, p_bind->sequence_number, ESME_ROK, false);
            }   break;
            case BIND_RECEIVER :
            {   bind_receiver_t *p_bind = (bind_receiver_t*)req;
                smpp_send_bind_transmitter_resp(sock, p_bind->system_id, p_bind->sequence_number, ESME_ROK, false);
            }   break;
            case BIND_TRANSCEIVER :
            {   bind_transceiver_t *p_bind = (bind_transceiver_t*)req;
                smpp_send_bind_transceiver_resp(sock, p_bind->system_id, p_bind->sequence_number, ESME_ROK, false);
            }   break;
            default:
            {   ret = smpp_send_response(sock, DATA_SM_RESP, ESME_RINVCMDID, &((generic_nack_t*)req)->sequence_number);
                ERROR(LOG_SCREEN | LOG_FILE ,"Request not allowed [%d:%d]", ((generic_nack_t*)req)->command_id, ((generic_nack_t*)req)->command_status)
            }   break;
        }
    }
    free(req);
    return (int) ret;
}

             //   if (p_sip->status_code == 202) { \
             //       printf("SEND SIP MESSAGE 111111 !!!!!!!!!!@@@@@@@@@\n"); \
             //       p_sip->cseq.number += 1; \
             //       p_sip->content_length = 8; \
             //       init_sip_from_t(&p_sip->from, "sip",p_sip->to.username, p_sip->to.host, p_sip->to.port, p_sip->from.tag); \
             //       init_sip_to_t(&p_sip->to, "sip",   NULL, "172.31.0.10", 5060, NULL); \
             //       char sms_deliver_report_default[9] = {'0','4','0','2','0','0','0','0','\0'}; \
             //       char *sms_deliver_report = malloc(p_sip->content_length); \
             //       memcpy(sms_deliver_report, sms_deliver_report_default, p_sip->content_length); \
             //       p_sip->message = sms_deliver_report; \
             //       printf("SEND SIP  MESSAGE 222222!!!!!!!!!!@@@@@@@@@\n"); \
             //       sip_send_request(p_session->p_sm->sock, p_session->p_sm->ip_origin, p_session->p_sm->port_origin, p_sip); \
             //       printf("SEND SIP  MESSAGE 222222!!!!!!!!!!@@@@@@@@@\n"); \
             //   } \

#define smpp_response_sm(data, p_session) \
    /*Get original message*/ \
    switch(p_session->p_sm->type){ \
        case I_SIP : \
        {   sip_message_t *p_sip = (sip_message_t*)p_session->p_sm->p_msg_origin; \
            if(data->command_status == ESME_ROK){ \
                p_sip->status_code = 202; \
                _strcpy(p_sip->reason_phrase, ACCEPTED_STR); \
            }else{ \
                p_sip->status_code = 406; \
                _strcpy(p_sip->reason_phrase, NOT_ACCEPTABLE_STR); \
            } \
            p_sip->content_length = 0; \
            /*p_sip->cseq.number++;*/ \
            int host_len = strlen(p_sip->from.host); \
            if (*(p_sip->from.host + host_len - 2) == '>') {\
                *(p_sip->from.host + host_len - 2) = '\0'; \
            } \
            if(sip_send_response(p_session->p_sm->sock, p_session->p_sm->ip_origin, p_session->p_sm->port_origin, p_sip) != -1){ \
                /*Clean DB*/ \
                db_delete_sm_by_id(p_session->p_sm->id); \
                /*Clean Memory*/ \
                free_sm_data(&p_session->p_sm); \
                map_erase(map_session_sip, p_sip->call_id.number);/*clean origin session*/ \
                map_erase(map_session_smpp, &((generic_nack_t*)p_session->p_msg_smpp)->sequence_number);/*clean forward session*/ \
            } \
        }   break; \
        case I_SMPP : \
        {   generic_nack_t *p_smpp = (smpp_session_t*)p_session->p_sm->p_msg_origin; \
            if(smpp_send_response(p_session->p_sm->sock, p_smpp->command_id & GENERIC_NACK, data->command_status, &p_smpp->sequence_number) != -1){ \
                /*Clean DB*/ \
                db_delete_sm_by_id(p_session->p_sm->id); \
                /*Clean Memory*/ \
                free_sm_data(p_session->p_sm); \
                map_erase(map_session_smpp, p_smpp->sequence_number);/*clean origin session*/ \
                map_erase(map_session_smpp, &((generic_nack_t*)p_session->p_msg_smpp)->sequence_number);/*clean forward session*/ \
            } \
        }   break; \
        case I_SIGTRAN : /*not implemented*/ \
            break; \
    }

int smpp_recv_processing_response(void *res){
    int ret = -1;
    if(res){
        //
        smpp_session_t *p_session = (smpp_session_t*)map_get(map_session_smpp, &((generic_nack_t*)res)->sequence_number);
        if(p_session){
            //I have a response to my request
            switch(((generic_nack_t*)res)->command_id){
                case DELIVER_SM_RESP :
                {   deliver_sm_resp_t *deliver = (deliver_sm_resp_t*)res;
                    smpp_response_sm(deliver,p_session);
                }   break;
                case SUBMIT_SM_RESP :
                {   submit_sm_resp_t *submit = (submit_sm_resp_t*)res;
                    smpp_response_sm(submit,p_session);
                }   break;
                case UNBIND_RESP :
                    //TODO
                    INFO(LOG_SCREEN, "UNBIND_RESP not allowed")
                    break;
                case ENQUIRE_LINK_RESP :
                    //TODO
                    INFO(LOG_SCREEN, "ENQUIRE_LINK_RESP not allowed")
                    break;
                case QUERY_SM_RESP :
                    //TODO
                    INFO(LOG_SCREEN, "QUERY_SM_RESP not allowed")
                    break;
                case REPLACE_SM_RESP :
                    //TODO
                    INFO(LOG_SCREEN, "REPLACE_SM_RESP not allowed")
                    break;
                case CANCEL_SM_RESP :
                    //TODO
                    INFO(LOG_SCREEN, "CANCEL_SM_RESP not allowed")
                    break;
                case BIND_TRANSMITTER_RESP :
                case BIND_RECEIVER_RESP :
                case BIND_TRANSCEIVER_RESP :
                    map_erase(map_session_smpp, &((generic_nack_t*)res)->sequence_number);
                    break;
                default : 
                    INFO(LOG_SCREEN, "Response not allowed[%d]", ((generic_nack_t*)res)->command_id)
                    break;
            }
        }
    }
    return (int) ret;
}

static void* smpp_recv_processing(void *data){
    void **all_data = (void**)data;
    config_smpp_t *p_config_smpp = (config_smpp_t*)all_data[1];
    if(DELIVER_SM == ((generic_nack_t*)all_data[0])->command_id  || SUBMIT_SM == ((generic_nack_t*)all_data[0])->command_id){//REQUEST : SUBMIT or DELIVER
        return (void* )smpp_recv_processing_request_sm(p_config_smpp->sock, p_config_smpp->name, p_config_smpp->data_coding, p_config_smpp->ip, p_config_smpp->port, all_data[0]);
    }else if(((generic_nack_t*)all_data[0])->command_id & GENERIC_NACK){//RESPONSE
        return (void*) smpp_recv_processing_response(all_data[0]);
    }else{//REQUEST
        return (void*) smpp_recv_processing_request(p_config_smpp->sock, all_data[0]);
    }
    free(all_data);
    return (void*) -1;
}

int smpp_engine(config_smpp_t *p_config_smpp){
    int   ret  = -1;
    void **data = NULL;
    void *data_smpp = NULL;

    if((ret = smpp_scan_sock(p_config_smpp->sock, &data_smpp)) > 0){
        data = (void**)calloc(3, sizeof(void*));
        data[0] = data_smpp;
        data[1] = p_config_smpp;
        threadpool_add(p_threadpool, smpp_recv_processing, data, 0);
    }
    return (int) ret;
}


/* utility function to convert hex character representation to their nibble (4 bit) values */
static uint8_t nibbleFromChar(char c)
{
	if(c >= '0' && c <= '9') return c - '0';
	if(c >= 'a' && c <= 'f') return c - 'a' + 10;
	if(c >= 'A' && c <= 'F') return c - 'A' + 10;
	return 255;
}

/* Convert a string of characters representing a hex buffer into a series of bytes of that real value */
uint8_t *hexStringToBytes(char *inhex)
{
	uint8_t *retval;
	uint8_t *p;
	int len, i;
	
    len = strlen(inhex) / 2;
	retval = malloc(len+1);
	for(i=0, p = (uint8_t *) inhex; i<len; i++) {
		retval[i] = (nibbleFromChar(*p) << 4) | nibbleFromChar(*(p+1));
		p += 2;
	}
    retval[len] = 0;
	return retval;
}

/**
 * Routing function
 */
 
 /* GSM 03.38 6.2.1 Character expanding (no decode!) */
static int gsm_7bit_expand(char *text, const uint8_t *user_data, uint8_t septet_l, uint8_t ud_hdr_ind)
{
	int i = 0;
	int shift = 0;
	uint8_t c;

	/* skip the user data header */
	if (ud_hdr_ind) {
		/* get user data header length + 1 (for the 'user data header length'-field) */
		shift = ((user_data[0] + 1) * 8) / 7;
		if ((((user_data[0] + 1) * 8) % 7) != 0)
			shift++;
		septet_l = septet_l - shift;
	}

	for (i = 0; i < septet_l; i++) {
		c =
			((user_data[((i + shift) * 7 + 7) >> 3] <<
			  (7 - (((i + shift) * 7 + 7) & 7))) |
			 (user_data[((i + shift) * 7) >> 3] >>
			  (((i + shift) * 7) & 7))) & 0x7f;

		*(text++) = c;
	}

	//*text = '\0';

	return i;
}

 
int send_sms_to_smpp(unsigned char* interface_name, sm_data_t *p_sm){
    int ret = -1;
    config_smpp_t  *p_config_smpp = map_get(cfg_smpp, interface_name);
    //create session + send submit_sm_t
    if(p_config_smpp && (p_config_smpp->command_id == BIND_TRANSMITTER || p_config_smpp->command_id == BIND_TRANSCEIVER) && p_sm){
        unsigned int *k_sequence_number = new_uint32();
        unsigned int data_coding = 0;
        unsigned char *msg = NULL;
        smpp_session_t *v_session = new_smpp_session_t();
        generic_nack_t *gen = (generic_nack_t*)calloc(1, sizeof(generic_nack_t));
        /*
        while(i < 16){
            size_t ret = 0;
            if((ret = conv_char_codec_str(p_sm->msg, (size_t)strlen((char*)p_sm->msg), cfg_main->system_charset, &msg, (size_t)0, p_config_smpp->data_coding[i])) != -1){
                data_coding = i;
                i = ret;
                break;
            }
            i++;
        }
        */
        data_coding = 0x00;
        uint8_t *sms_map = hexStringToBytes((char *)p_sm->msg);
        int offset = 0;
        int number_len = 0;
        int number_len_oct = 0;

        //****rp-da TLV****
        printf("RP-DA : T:[0x%02X] L:[0x%02X] V:", sms_map[0], sms_map[1]);
        print_hex_memory(sms_map + 2, sms_map[1]);
        offset += 2; // TL
        offset += sms_map[offset-1]; // V
        //******************
        
        //****rp-do TLV****
        printf("RP-DO : T:[0x%02X] L:[0x%02X] V:", sms_map[offset], sms_map[offset+1]);
        print_hex_memory(sms_map + offset + 2, sms_map[offset+1]);
        offset += 2; // TL
        offset += sms_map[offset-1]; // V
        //******************
        
        //**** RP data Type and Length****
        printf("RP-DATA : T: [0x%02X] L: [0x%02X]\n", sms_map[offset], sms_map[offset+1]);
        offset += 2; //TL
        //******************
    
        printf("RP-DATA : V:[start]\n"); 
           
        //**** TPDU first octet ****
        printf("TPDU : First octet : [0x%02X] \n", sms_map[offset]);
        int esm_class = 0x00; // UDHI = 0
        if (sms_map[offset]&0x40) {
            esm_class = 0x40; // UDHI = 1
        }
        offset += 1; // tpdu first octet
        //******************

        //**** TPDU TP-OA ****
        printf("TPDU : TP-OA : LEN : [0x%02X] \n", sms_map[offset]);
        offset += 1; // tpdu TP-OA: number length
        printf("TPDU : TP-OA : TYPE : [0x%02X] \n", sms_map[offset]);
        int tpdu_tp_oa_type = sms_map[offset];
        offset += 1; // tpdu TP-OA: number type
        number_len = sms_map[offset-2];
        if (number_len % 2) {
            /* number_len is odd */
            number_len_oct = (number_len + 1)/2; // tpdu TP-OA: number
        } else {
            number_len_oct = number_len/2; // tpdu TP-OA: number
        }
        if (tpdu_tp_oa_type == 0x91) {
            // decode international number
            char* src_addr = malloc(number_len + 1);
            decode_bcd_number(src_addr, number_len + 1, sms_map + offset,  number_len_oct);
            p_sm->src = (unsigned char*)src_addr;
        } else if(tpdu_tp_oa_type == 0xd1) {
            char* src_addr = malloc(4); // Alphanumeric change to 100
            char smart_number[4] = {'1','0','0','\0'};
            memcpy(src_addr, smart_number, 4);
            p_sm->src = (unsigned char*)src_addr;
        }
        printf("TPDU : TP-OA : NUMBER : ");
        print_hex_memory(sms_map + offset, number_len_oct);
        offset += number_len_oct;
        //**********************

        //**** TPDU TP-PID ****
        printf("TPDU : TP-PID : [0x%02X] \n", sms_map[offset]);
        offset += 1; // tpdu TP-PID
        //**********************

        //**** TPDU TP-DSC ****
        printf("TPDU : TP-DSC : [0x%02X] \n", sms_map[offset]);
        offset += 1; // tpdu TP-DSC
        //**********************

        //**** TPDU TP-SCTS ****
        printf("TPDU : TP-SCTS : ");
        print_hex_memory(sms_map + offset, 7);       
        offset += 7; // tpdu TP-SCTS
        //**********************
        
        //**** TPDU TP-User-data ****
        printf("TPDU : TP-User-data : Len : [0x%02X] \n", sms_map[offset]);
        int septet_len = sms_map[offset];
        int tp_user_data_len_oct = (sms_map[offset] * 7 + 7) / 8;
        printf("TPDU : TP-User-data : Len Octets: [0x%02X] \n", tp_user_data_len_oct);
        offset += 1; //TP-user-data-len

        printf("TPDU : TP-User-data : Data : ");
        print_hex_memory(sms_map + offset, tp_user_data_len_oct);
        msg = (char*)malloc(septet_len);        
        gsm_7bit_expand(msg, sms_map + offset, septet_len, 0);
        //**********************

        printf("RP-DATA : V : [end] \n");

        gen->sequence_number = get_sequence_number();
        *k_sequence_number = gen->sequence_number;
        v_session->command_id = SUBMIT_SM;
        v_session->p_msg_smpp = gen;
        v_session->p_sm = p_sm;
        map_set(map_session_smpp, k_sequence_number, v_session);
        ret = smpp_send_submit_sm(p_config_smpp->sock, p_sm->src, p_sm->dst, msg ? msg : p_sm->msg, septet_len, &(gen->sequence_number), data_coding, p_config_smpp->ton, p_config_smpp->npi, p_config_smpp->ton, p_config_smpp->npi, esm_class);
    }
    return (int) ret;
}



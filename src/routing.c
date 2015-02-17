/////////////////////////////
//  SCRIPT ROUTING SAMPLE  //
/////////////////////////////

/**
 * GLOBAL VARIABLE
 * 
 * MAP<char*,socket> = interface_name -> p_socket (TODO : Map Interfaces with p_(sip/smpp)_socket)
 * count_sms         = SMS number in the DB
 */

//send_sms_to_sip(I_LISTEN_SIP, msisdn_src, msisdn_dst, message, ip_remote, port_remote);
//send_sms_to_smpp(I_CONNECTION_SMPP, msisdn_src, msisdn_dst, message);

//interface name (cf INI file)
#define I_CONNECTION_SMPP "SMPP01"
#define I_LISTEN_SIP      "SIP_H_01"

/////////////////
// Foreward sample
/////

/**
 * \brief This function is used for routed all SMS/Sip Message
 * 
 * \param interface_name : where are comming the message
 * \param msisdn_src   : Source phone number
 * \param msisdn_dst   : Destination phone number
 * \param message      : SMS Message
 */
int routing(const unsigned char *interface_name, const unsigned char *origin_ip, const unsigned int *origin_port, const unsigned char *msisdn_src, const unsigned char *msisdn_dst, const unsigned char *message){
    if(strcmp(interface_name, I_CONNECTION_SMPP) == 0){
        //send to SIP interface
        return (int) send_sms_to_sip(I_LISTEN_SIP, msisdn_src, msisdn_dst, message, "192.168.0.1", 5090);
    }else if(strcmp(interface_name, I_LISTEN_SIP) == 0){
        //send to SMPP interface
        return (int) send_sms_to_smpp(I_CONNECTION_SMPP, msisdn_src, msisdn_dst, message);
    }
    return (int) -1;
}


/// END SCRIPT ROUTING SAMPLE
/* MODULE NAME:  snmp_helper.c
 * PURPOSE:
 *    for ucentral middleware process.
 *
 * NOTES:
 *
 * REASON:
 * Description:
 * HISTORY
 *    2023/02/03 - Saulius P., Created
 *
 * Copyright(C)      Accton Corporation, 2023
 */
/* INCLUDE FILE DECLARATIONS
 */
#include <math.h>
#include "snmp_helper.h"
#include "api_print.h"

static struct snmp_session session, *ss;

int snmph_session_start(void) {
    init_snmp("ucmw_snmp");
    snmp_sess_init( &session );

    session.peername = "127.0.0.1";
    session.version = SNMP_VERSION_2c;
    session.community = (unsigned char*)"private";
    session.community_len = strlen((char*)session.community);

    ss = snmp_open(&session);

    if (ss) {
        return STAT_SUCCESS;
    } else {
        return STAT_ERROR;
    }
}

int snmph_set(const char *oid_str, char type, char *value) {
    netsnmp_pdu *pdu, *response = NULL;
    size_t name_length;
    oid name[MAX_OID_LEN];
    int status, exitval = 0;

    pdu = snmp_pdu_create(SNMP_MSG_SET);
    name_length = MAX_OID_LEN;
    if (snmp_parse_oid(oid_str, name, &name_length) == NULL){
        snmp_perror(oid_str);
        return -1;
    } else{
        if (snmp_add_var(pdu, name, name_length, type, value)) {
            snmp_perror(oid_str);
            return -1;
        }
    }
    
    status = snmp_synch_response(ss, pdu, &response);
    if (status == STAT_SUCCESS) {
        if (response->errstat != SNMP_ERR_NOERROR) {
            fprintf(stderr, "Error in packet.\nReason: %s\n",
                    snmp_errstring(response->errstat));
            exitval = 2;
        }
    } else if (status == STAT_TIMEOUT) {
        fprintf(stderr, "Timeout: No Response from %s\n",
                session.peername);
        exitval = 1;
    } else {                    /* status == STAT_ERROR */
        snmp_sess_perror("snmpset", ss);
        exitval = 1;
    }
    
    if (response)
        snmp_free_pdu(response);

    return exitval;
}

int snmph_set_array(const char *oid_str, char type, const u_char *value, size_t len) {
    netsnmp_pdu *pdu, *response = NULL;
    size_t name_length;
    oid name[MAX_OID_LEN];
    int status, exitval = 0;

    pdu = snmp_pdu_create(SNMP_MSG_SET);
    name_length = MAX_OID_LEN;
    if (snmp_parse_oid(oid_str, name, &name_length) == NULL){
        snmp_perror(oid_str);
        return -1;
    } else{
        if (!snmp_pdu_add_variable(pdu, name, name_length, type, value, len)) {
            snmp_perror(oid_str);
            return -1;
        }
    }

    status = snmp_synch_response(ss, pdu, &response);
    if (status == STAT_SUCCESS) {
        if (response->errstat != SNMP_ERR_NOERROR) {
            fprintf(stderr, "Error in packet.\nReason: %s\n",
                    snmp_errstring(response->errstat));
            exitval = 2;
        }
    } else if (status == STAT_TIMEOUT) {
        fprintf(stderr, "Timeout: No Response from %s\n",
                session.peername);
        exitval = 1;
    } else {                    /* status == STAT_ERROR */
        snmp_sess_perror("snmpset", ss);
        exitval = 1;
    }
    
    if (response)
        snmp_free_pdu(response);

    return exitval;
}

int snmph_get(const oid *req_oid, size_t req_oid_len, struct snmp_pdu **response) {
    struct snmp_pdu *request = snmp_pdu_create(SNMP_MSG_GET);
    snmp_add_null_var(request, req_oid, req_oid_len);

    int status = snmp_synch_response(ss, request, response);

    if (*response && (*response)->errstat != SNMP_ERR_NOERROR) {
        print_err("Error 1, response with error: %d,  %ld\n", status, (*response)->errstat);
        snmp_free_pdu(*response);
        return STAT_ERROR;
    }

    if (!(*response)) {
        print_err("Error 2: empty SNMP response\n");
        return STAT_ERROR;
    }
    
    if (status != STAT_SUCCESS) {
        print_err("Error 3: bad response status: %d\n", status);
        snmp_free_pdu(*response);
    }

    if (!(*response)->variables) {
        print_err("Error 4: empty variable list in response\n");
        snmp_free_pdu(*response);
        return STAT_ERROR;
    }

    print_debug("Default return: %d\n", status);
    return status;
}

int snmph_get_argstr(const char *oid_str, struct snmp_pdu **response) {
    oid name[MAX_OID_LEN];
    size_t name_length = MAX_OID_LEN;
    
    if (snmp_parse_oid(oid_str, name, &name_length) == NULL) {
        snmp_perror(oid_str);
        return -1;
    }
    
    struct snmp_pdu *request = snmp_pdu_create(SNMP_MSG_GET);
    snmp_add_null_var(request, name, name_length);
 
    int status = snmp_synch_response(ss, request, response);

    if (*response && (*response)->errstat != SNMP_ERR_NOERROR) {
        print_err("Error 1, response with error: %d,  %ld\n", status, (*response)->errstat);
        snmp_free_pdu(*response);
        return STAT_ERROR;
    }

    if (!(*response)) {
        print_err("Error 2: empty SNMP response\n");
        return STAT_ERROR;
    }
    
    if (status != STAT_SUCCESS) {
        print_err("Error 3: bad response status: %d\n", status);
        snmp_free_pdu(*response);
    }

    if (!(*response)->variables) {
        print_err("Error 4: empty variable list in response\n");
        snmp_free_pdu(*response);
        return STAT_ERROR;
    }

    print_debug("Default return: %d\n", status);
    return status;
}

int snmph_get_single_string(const oid *req_oid, size_t req_oid_len, char *buf, int buf_len) {
    struct snmp_pdu *response = NULL;
    int status = snmph_get(req_oid, req_oid_len, &response);

    if (status != STAT_SUCCESS) {
        return status;
    }

    memset(buf, 0, buf_len);
    strncpy(buf, (char*)response->variables->val.string, (int) fmin(buf_len, response->variables->val_len));

    // if (response)
    snmp_free_pdu(response);

    return STAT_SUCCESS;
}

int snmph_get_bulk(const oid *req_oid, size_t req_oid_len, int max, struct snmp_pdu **response) {
    struct snmp_pdu *request = snmp_pdu_create(SNMP_MSG_GETBULK);
    request->non_repeaters = 0;
    request->max_repetitions = max;
    snmp_add_null_var(request, req_oid, req_oid_len);

    int status = snmp_synch_response(ss, request, response);

    // printf("Bulk status: %d\n", status);

    if (status == 1) {
        snmp_sess_perror("snmpbulkget", ss);
    }

    if (*response && (*response)->errstat != SNMP_ERR_NOERROR) {
        print_err("Error 1, bulk response error: %d,  %ld\n", status, (*response)->errstat);
        snmp_free_pdu(*response);
        return STAT_ERROR;
    }

    if (!(*response)) {
        print_err("Error 2: empty bulk response\n");
        return STAT_ERROR;
    }
    
    if (status != STAT_SUCCESS) {
        print_err("Error 3, bad bulk status: %d\n", status);
        snmp_free_pdu(*response);
    }

    if (!(*response)->variables) {
        print_err("Error 4, empty bulk variables\n");
        snmp_free_pdu(*response);
        return STAT_ERROR;
    }

    print_debug("Default bulk return: %d\n", status);
    return status;
}

int snmph_walk(const char *oid_str, void *buf, int *num) {
    netsnmp_pdu *pdu, *response = NULL;
    netsnmp_variable_list *vars;
    oid name[MAX_OID_LEN];
    size_t name_length = MAX_OID_LEN;
    int running = 1;
    int status = 0;
    enum snmp_walk_node node = SNMP_WALK_NODE_NONE;

    if (snmp_parse_oid(oid_str, name, &name_length) == NULL) {
        snmp_perror(oid_str);
        return -1;
    }

    if (!strcmp(oid_str, O_STR_VLAN_STATUS))
        node = SNMP_WALK_NODE_VLAN_STATUS;
    else if (!strcmp(oid_str, O_STR_POE_PORT_ENABLE))
        node = SNMP_WALK_NODE_POE_PORT_ENABLE;

    *num = 0;  

    while (running) {
        /*
         * create PDU for GETNEXT request and add object name to request 
         */
        pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
        snmp_add_null_var(pdu, name, name_length);

        /*
         * do the request 
         */
        status = snmp_synch_response(ss, pdu, &response);

        if (status == STAT_SUCCESS) {
            if (response->errstat == SNMP_ERR_NOERROR) {
                /*
                 * check resulting variables 
                 */
                for (vars = response->variables; vars;
                     vars = vars->next_variable) {

                    if (node == SNMP_WALK_NODE_VLAN_STATUS)
                    {
                        if ((vars->name[12]==O_VLAN_STATUS[12]) && (vars->name_length==(OID_LENGTH(O_VLAN_STATUS)+1)))
                        {
                            ((int*)buf)[(*num)++] = vars->name[13];
                        }
                        else
                            running = 0;
                    }
                    else if (node == SNMP_WALK_NODE_POE_PORT_ENABLE)
                    {
                    	if ((vars->name[10]==O_POE_PORT_ENABLE[10]) && (vars->name_length==(OID_LENGTH(O_POE_PORT_ENABLE)+1)))
                      {
                          (*num)++;
                      }
                      else
                          running = 0;
                    }
                    else
                        running = 0;

                    memmove((char *) name, (char *) vars->name, vars->name_length * sizeof(oid));
                    name_length = vars->name_length;

                    //print_variable(vars->name, vars->name_length, vars);
                }
            } else {
                  running = 0;
            }
        } else if (status == STAT_TIMEOUT) {
              fprintf(stderr, "Timeout: No Response from %s\n",
                      session.peername);
              running = 0;
              status = 1;
         
        } else {                /* status == STAT_ERROR */
              snmp_sess_perror("snmpwalk", ss);
              running = 0;
              status = 1;
        }
        if (response)
            snmp_free_pdu(response);
    }

    return status;
}

void snmph_session_close(void) {
    snmp_close(ss);
}


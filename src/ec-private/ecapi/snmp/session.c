#include "api_session.h"
#include "snmp_helper.h"

int session_start() {
    return snmph_session_start();
}

void session_close() {
    snmph_session_close();
}

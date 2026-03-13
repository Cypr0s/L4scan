#include "util.h"

void print_formated(char* ip_adress, char* port_number, char* protocol, char* status) {
    fprintf(stdout,"%s %s %s %s", ip_adress, port_number, protocol, status);
}

#include "l4scan.h"

const char* help_message = "SOMEBODY HELP ME PLEASE!";
#define NUMBER_SYSTEM 10

int main(int argc, char** argv) {
    // handle input arguments
    Scanner scanner;
    if(parse_arguments(argc, argv, &scanner)) {
        return EXIT_INVALID_ARGUMENT;
    }
}

ExitEnum parse_arguments(int argc, char** argv, ScannerPtr scanner) {
    if(argc <= 1) {
        return EXIT_INVALID_ARGUMENT;
    }

    scanner->host = NULL;
    scanner->interface = NULL;
    scanner->timeout_time = 1000;
    
    for(int i = 1; i < argc; i++) {
        char* argument = argv[i];
        // interface argument
        if(strcmp(argument, "-i") == 0) {
            if(i + 1 >= argv) {
                return EXIT_SUCCESS;
            }
            scanner->interface = argv[i + 1];
            
        }
        // help
        else if(strcmp(argument, "--help") == 0 || strcmp(argument, "-h")) {
            fprintf(stdout, "%s", help_message);
            return EXIT_SUCCESS;
        }
        // TCP ports
        else if(strcmp(argument, "-t") == 0) {
            
        }
        // UDP port handling
        else if(strcmp(argument, "-u") == 0) {
            if(i + 1 >= argc) {
                fprintf(stderr, "Invalid argument, `-u` parameter needs a value");
                return EXIT_INVALID_ARGUMENT;
            }

            if(convert_str_to_nums(argv[i+1],scanner->udp_arr)) {
                fprintf(stderr, 
                    "Invalid argument, value of `-u` - `%s` is invalid input", 
                    argv[i + 1]
                );
                return EXIT_INVALID_ARGUMENT;
            }

        }
        // timeout time param
        else if(strcmp(argument, "-w")) {
            if(i + 1 >= argc) {
                fprintf(stderr, "Invalid argument, `-w` parameter needs a value");
                return EXIT_INVALID_ARGUMENT;
            }
            // convert value to int
            char* check;
            long val;
            val = strtol(argv[i + 1], &check, NUMBER_SYSTEM);
            if (*check != '\0' || val <= 0 || val > INT_MAX) {
                fprintf(stderr, 
                    "Invalid argument, value of `-w` - `%s` is invalid input", 
                    argv[i + 1]
                );
                return EXIT_INVALID_ARGUMENT;
            }
            scanner->timeout_time = (int) val;
            i++;
        }
        // HOST
        else {

        }
    }
    return EXIT_SUCCESS;
}

ExitEnum convert_str_to_nums(const char* input, unsigned long* arr) {
    char* string_check_ptr;
    long first_value = strtol(input, &string_check_ptr, NUMBER_SYSTEM);
    // number is in invalid 
    if(first_value <= 0 || first_value > MAX_PORTS) {
        return EXIT_INVALID_ARGUMENT;
    }

    // whole input was consumed (only one number) 
    if(*string_check_ptr == '\0') {

        // move 1 to corresponding bit in bitmap
        ADD_TO_ARR(arr, first_value);
        return EXIT_SUCCESS;
    }

    // `-` found , range of ports a - b
    if(*string_check_ptr == '-') {
        char* end_ptr = string_check_ptr + 1;
        // find the end of range
        long end_value = strtol(end_ptr, &string_check_ptr, NUMBER_SYSTEM);
        if(end_value <= 0 || end_value >= USHRT_MAX ||
                *string_check_ptr != '\0' ||
                (unsigned long) first_value > (unsigned long) end_value) {
            return EXIT_INVALID_ARGUMENT;
        }

        // set all bits in range to 1
        for(; (unsigned long) first_value <= (unsigned long) end_value; first_value++) {
            ADD_TO_ARR(arr, first_value);
        }
        return EXIT_SUCCESS;
    }
    // multiple ports a, b, c
    if (*string_check_ptr == ',') {
        // not proud of this
        char* str = string_check_ptr + 1;
        ADD_TO_ARR(arr, first_value);
        while(1) {
            first_value = strtol(str, &string_check_ptr, NUMBER_SYSTEM);
            //success
            if(*string_check_ptr == '\0') {
                ADD_TO_ARR(arr, first_value);
                return EXIT_SUCCESS;
            }
            // errors
            if(first_value <= 0 || first_value > USHRT_MAX || 
                    *string_check_ptr != ',' || 
                    string_check_ptr == str) {
                return EXIT_INVALID_ARGUMENT;
            }

            ADD_TO_ARR(arr, first_value);
            str = string_check_ptr + 1;
        }
    }
    return EXIT_FAILURE;
}

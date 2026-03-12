#include "parse.h"

const char* help_message = "SOMEBODY HELP ME PLEASE!\n";

ExitEnum parse_arguments(int argc, char** argv, ScannerPtr scanner) {
    if(argc <= 1) {
        fprintf(stderr, "No arguments provided, try using --help\n");
        return EXIT_INVALID_ARGUMENT;
    }

    scanner->timeout_time = 1000;
    
    for(int i = 1; i < argc; i++) {
        char* argument = argv[i];
        // interface argument
        if(!strcmp(argument, "-i")) {
            if(scanner->parameter_flags & INTERFACE_FLG) {
                fprintf(stderr, "Multiple uses of arg `%s`\n", argument);
                return EXIT_INVALID_ARGUMENT;
            }
            scanner->parameter_flags |= INTERFACE_FLG;

            if(i + 1 >= argc) {
                return EXIT_SUCCESS;
            }
            // empty -i
            if(!strcmp(argv[i + 1], "-w") || 
            !strcmp(argv[i + 1], "-i") || 
            !strcmp(argv[i + 1], "-t") || 
            !strcmp(argv[i + 1], "-u") || 
            !strcmp(argv[i + 1], "-h") ||
            !strcmp(argv[i + 1], "--help")) {
                continue;
            }
            scanner->interface = argv[++i];
        }
        // help
        else if(!strcmp(argument, "--help") || !strcmp(argument, "-h")) {
            fprintf(stdout, "%s", help_message);
            scanner->parameter_flags |= HELP_FLG;
            return EXIT_SUCCESS;
        }
        // TCP ports
        else if(!strcmp(argument, "-t")) {
            if( scanner->parameter_flags & TCP_FLG) {
                fprintf(stderr, "Multiple uses of arg `%s`\n", argument);
                return EXIT_INVALID_ARGUMENT;
            }

            if(i + 1 >= argc) {
                fprintf(stderr, "Invalid argument, `-t` parameter needs a value\n");
                return EXIT_INVALID_ARGUMENT;
            }

            if(convert_str_to_nums(argv[++i],scanner->tcp_arr)) {
                fprintf(stderr, 
                    "Value of `%s` Needs to be a number input `%s` is Not a number\n",
                    argument, argv[i]
                );
                return EXIT_INVALID_ARGUMENT;
            }
            scanner->parameter_flags |= TCP_FLG;
        }
        // UDP port handling
        else if(!strcmp(argument, "-u")) {
            if(scanner->parameter_flags & UDP_FLG) {
                fprintf(stderr, "Multiple uses of arg `%s`\n", argument);
                return EXIT_INVALID_ARGUMENT;
            }

            if(i + 1 >= argc) {
                fprintf(stderr, "Invalid argument, `-u` parameter needs a value\n");
                return EXIT_INVALID_ARGUMENT;
            }

            if(convert_str_to_nums(argv[++i],scanner->udp_arr)) {
                fprintf(stderr, 
                    "Value of `%s` Needs to be a number, input `%s` is Not a number\n",
                    argument, argv[i]
                );
                return EXIT_INVALID_ARGUMENT;
            }
            scanner->parameter_flags |= UDP_FLG;
        }
        // timeout time
        else if(!strcmp(argument, "-w")) {
            if(scanner->parameter_flags & TIMEOUT_FLG) {
                fprintf(stderr, "Multiple uses of arg `%s`\n", argument);
                return EXIT_INVALID_ARGUMENT;
            }

            if(i + 1 >= argc) {
                fprintf(stderr, "Invalid argument, `-w` parameter needs a value\n");
                return EXIT_INVALID_ARGUMENT;
            }
            // convert value to int
            char* check;
            long val;
            errno = 0;
            val = strtol(argv[i + 1], &check, NUMBER_SYSTEM);
            if (errno != 0 || 
                *check != '\0' || 
                val <= 0 ||
                val > INT_MAX || 
                check == argv[i + 1]) 
            {
                fprintf(stderr, 
                    "value of `-w` Needs to be a number `%s` is Not a number\n", 
                    argv[i + 1]
                );
                return EXIT_INVALID_ARGUMENT;
            }

            scanner->timeout_time = (unsigned int) val;
            scanner->parameter_flags |= TIMEOUT_FLG;
            i++;
        }
        else if(argument[0] == '-') {
            fprintf(stderr, "`%s` is not a valid argument\n", argument);
            return EXIT_INVALID_ARGUMENT;
        }
        // HOST
        else {
            if(scanner->parameter_flags & HOSTNAME_FLG) {
                fprintf(stderr, "Multiple hostnames provided, try using parameter -help\n");
                return EXIT_INVALID_ARGUMENT;
            }
    
            scanner->hostname = argv[i];
            scanner->parameter_flags |= HOSTNAME_FLG;
        }
    }

    if(!(scanner->parameter_flags & HOSTNAME_FLG)) {
        fprintf(stderr, "No hostname provided, Hostname is required\n");
        return EXIT_INVALID_ARGUMENT;
    }
    if(!(scanner->parameter_flags & INTERFACE_FLG)) {
        fprintf(stderr, "No interface provided, Interface is required\n");
        return EXIT_INVALID_ARGUMENT;
    }
    if(!(scanner->parameter_flags & TCP_FLG) && 
        !(scanner->parameter_flags & UDP_FLG)) 
        {
        fprintf(stderr, "No ports specified, you need to provide atleast one port to scan\n");
        return EXIT_INVALID_ARGUMENT;
    }
    return EXIT_SUCCESS;
}

ExitEnum convert_str_to_nums(const char* input, unsigned long* arr) {
    char* string_check_ptr;
    errno = 0;
    long first_value = strtol(input, &string_check_ptr, NUMBER_SYSTEM);
    // number is in invalid 
    if(errno != 0 || first_value <= 0 || first_value > MAX_PORTS || string_check_ptr == input) {
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
        errno = 0;
        long end_value = strtol(end_ptr, &string_check_ptr, NUMBER_SYSTEM);
        if( errno != 0 || 
            end_value <= 0 || 
            end_value > MAX_PORTS || 
            *string_check_ptr != '\0' ||
            (unsigned long) first_value > (unsigned long) end_value ||
            end_ptr == string_check_ptr)
        {
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
            // strtol errors
            if(errno != 0 || 
                first_value < 0 || 
                first_value > MAX_PORTS || 
                string_check_ptr == str) 
            {
                return EXIT_INVALID_ARGUMENT;
            }
            // add to array (0 if strtol failed)
            ADD_TO_ARR(arr, first_value);
            if(*string_check_ptr == '\0') {
                return EXIT_SUCCESS;
            }
            // strtol error 
            if(*string_check_ptr != ',') {
                return EXIT_INVALID_ARGUMENT;
            }

            str = string_check_ptr + 1;
        }
    }
    return EXIT_FAILURE;
}

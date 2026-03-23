/** -------------- IPK 1. project - L4 Scanner -----------------
 * @file    parse.c
 * @author  Kristian Luptak <xluptak00>
 * @date    creation:   11.3.2026
 *          updated:    15.3.2026
 * @brief   File handles the parsing of input arguments, 
 *          loading important information into Scanner struct 
 *          which is used further in other module.
 */


#include "parse.h"


const char* help_message =  " USAGE: ./ipk-L4-scan -i INTERFACE [-u PORTS] [-t PORTS] HOST [-w TIMEOUT] [-h | --help] where\n\n"
                            " REQUIRED PARAMETERS: -i \n"
                            "                      HOSTNAME\n"
                            "                      atleast one port -u or -t\n\n"
                            "-i INTERFACE   must be a valid interface\n"
                            " HOSTNAME      must be a valid hostname\n"
                            "-u PORTS       are udp scanned ports\n"
                            "-t PORTS       are tcp scanner ports\n"
                            "-w TIMEOUST    is timeout in milisecons\n";

/**
 * @def     parse_arguments
 * @brief   Parses input arguments, loads information into Scanner struct,
 *          returns ERR_INVALID_ARUMENT when invalid argument is inputted.
 * @param   argc - count ofinput arguments passed from main()
 * @param   argv - input arguments passed from main()
 * @param   scanner - pinter to Scanner struct where important parsed information is stored
 *                    (eg. interface name, hostname name, bitmap of ports)
 * @return  ERR_SUCCESS(0) if parsing was successful or help argument was provided
 *          ERR_INVALID_ARGUMENT(2) if there was either invalid Argument, invalid argument Value,
 *          Multiple uses of any argument or no Required argument was 
 *          provided(hostname, interface atleast one of TCP/UDP ports)
 */
ExitEnum parse_arguments(int argc, char** argv, ScannerPtr scanner) {
    if(argc <= 1) {
        fprintf(stderr, "No arguments provided, try using --help\n");
        return ERR_INVALID_ARGUMENT;
    }
    // default scanner timeout time
    scanner->timeout_time = 1000;
    
    // loop through arguments
    for(int i = 1; i < argc; i++) {
        char* argument = argv[i];
        // interface argument (-i)
        if(!strcmp(argument, "-i")) {

            // multiple uses check
            if(scanner->parameter_flags & INTERFACE_FLG) {
                fprintf(stderr, "Multiple uses of arg `%s`\n", argument);
                return ERR_INVALID_ARGUMENT;
            }

            scanner->parameter_flags |= INTERFACE_FLG;

            // i has no value print all interfacec and exit
            if(i + 1 >= argc) {
                return ERR_SUCCESS;
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

            /*  set interface name (interface name handling is done in module 
                inteface.c called in main()) */ 
            scanner->interface_name = argv[++i];
        } // interface argument

        //  help argument (-h, --help)
        else if(!strcmp(argument, "--help") || !strcmp(argument, "-h")) {
            // help argument has highest priority(if provided, all other arguments are ignored)
            fprintf(stdout, "%s", help_message);
            scanner->parameter_flags |= HELP_FLG;

            return ERR_SUCCESS;
        } // help argument

        // TCP argument (-t)
        else if(!strcmp(argument, "-t")) {

            // multiple uses check
            if( scanner->parameter_flags & TCP_FLG) {
                fprintf(stderr, "Multiple uses of arg `%s`\n", argument);
                return ERR_INVALID_ARGUMENT;
            }

            // parameter without value
            if(i + 1 >= argc) {
                fprintf(stderr, "Invalid argument, `-t` parameter needs a value\n");
                return ERR_INVALID_ARGUMENT;
            }

            // set TCP flag
            scanner->parameter_flags |= TCP_FLG;

            // converts range of ports string(eg. 80-443 or 67, 68, 69 or 65536) into bitmap
            if(convert_str_to_nums(argv[++i],scanner->tcp_arr, &(scanner->tcp_count))) {
                fprintf(stderr, 
                    "Value of `%s` Needs to be a number input `%s` is Not a number\n",
                    argument, argv[i]
                );
                return ERR_INVALID_ARGUMENT;
            }
        } // TCP argument

        // UDP argument handling (-u)
        else if(!strcmp(argument, "-u")) {

            // multiple uses check
            if(scanner->parameter_flags & UDP_FLG) {
                fprintf(stderr, "Multiple uses of arg `%s`\n", argument);
                return ERR_INVALID_ARGUMENT;
            }

            // parameter without value
            if(i + 1 >= argc) {
                fprintf(stderr, "Invalid argument, `-u` parameter needs a value\n");
                return ERR_INVALID_ARGUMENT;
            }

            // set UDP flag
            scanner->parameter_flags |= UDP_FLG;

            // converts range of ports string(eg. 80-443 or 67, 68, 69 or 65536) into bitmap
            if(convert_str_to_nums(argv[++i],scanner->udp_arr, &(scanner->udp_count))) {
                fprintf(stderr, 
                    "Value of `%s` Needs to be a number, input `%s` is Not a number\n",
                    argument, argv[i]
                );
                return ERR_INVALID_ARGUMENT;
            }
        } // UDP agrument

        // timeout argument (-w))
        else if(!strcmp(argument, "-w")) {

            // multiple uses check
            if(scanner->parameter_flags & TIMEOUT_FLG) {
                fprintf(stderr, "Multiple uses of arg `%s`\n", argument);
                return ERR_INVALID_ARGUMENT;
            }

            if(i + 1 >= argc) {
                fprintf(stderr, "Invalid argument, `-w` parameter needs a value\n");
                return ERR_INVALID_ARGUMENT;
            }

            // convert value to int
            char* check;
            long val;
            errno = 0;
            val = strtol(argv[i + 1], &check, NUMBER_SYSTEM);
            // strtol errors check, boundary checks
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

                return ERR_INVALID_ARGUMENT;
            }

            scanner->timeout_time = (unsigned int) val;
            scanner->parameter_flags |= TIMEOUT_FLG;
            i++;
        } // timeout argument

        // invalid arguments (anytihng that starts with `-` and is not defined higher)
        else if(argument[0] == '-') {
            fprintf(stderr, "`%s` is not a valid argument\n", argument);
            return ERR_INVALID_ARGUMENT;
        }  // invalid argument

        // hostname argument (ip address or hostname)
        else {
            // hostname defined multiple times
            if(scanner->parameter_flags & HOSTNAME_FLG) {
                fprintf(stderr, "Multiple hostnames provided, try using parameter -help\n");
                return ERR_INVALID_ARGUMENT;
            }
    
            scanner->hostname = argv[i];
            scanner->parameter_flags |= HOSTNAME_FLG;
        } // hostname argument
    } // argument for loop


    // required arguments checking
    if(!(scanner->parameter_flags & HOSTNAME_FLG)) {
        fprintf(stderr, "No hostname provided, Hostname is required\n");
        return ERR_INVALID_ARGUMENT;
    }

    if(!(scanner->parameter_flags & INTERFACE_FLG)) {
        fprintf(stderr, "No interface provided, Interface is required\n");
        return ERR_INVALID_ARGUMENT;
    }

    if(!(scanner->parameter_flags & TCP_FLG) && 
        !(scanner->parameter_flags & UDP_FLG)) 
        {
        fprintf(stderr, "No ports specified, you need to provide atleast one port to scan\n");
        return ERR_INVALID_ARGUMENT;
    }

    return ERR_SUCCESS;
}   // parse_arguments


/**
 * @def     convert_str_to_nums
 * @brief   converts range of ports string(eg. 80-443 or 67, 68, 69 or 65536) 
 *          into bitmap which is stored in arr parameter
 * @param   input - string which is converted to bitmap
 * @param   arr - bitmap (longs) from struct Scanner where result bits are set to 1
 * @return  ERR_INVALID_ARGUMENT(2) upon strtol errors or invalid input
 *          (eg. number is out of range for ports or invalid characters).
 *          ERR_SUCCESS(0) if no errors happened
 */
ExitEnum convert_str_to_nums(const char* input, unsigned long* arr, unsigned short* count) {
    char* string_check_ptr; // strtol checker
    errno = 0;
    long first_value = strtol(input, &string_check_ptr, NUMBER_SYSTEM);

    // strtol errors check, boundary checks
    if(errno != 0 || first_value <= 0 || first_value > MAX_PORTS || string_check_ptr == input) {
        return ERR_INVALID_ARGUMENT;
    }

    // whole input was consumed (only one number) 
    if(*string_check_ptr == '\0') {

        // move 1 to corresponding bit in bitmap
        ADD_TO_ARR(arr, first_value);
        *count = 1U;
        return ERR_SUCCESS;
    } // single port

    // `-` found , range of ports a - b
    if(*string_check_ptr == '-') {
    
        char* end_ptr = string_check_ptr + 1; // will store end of range value
        errno = 0;
    
        // error in string_check_ptr
        long end_value = strtol(end_ptr, &string_check_ptr, NUMBER_SYSTEM);

        // strtol errors check, boundary checks
        if( errno != 0 || 
            end_value <= 0 || 
            end_value > MAX_PORTS || 
            *string_check_ptr != '\0' ||
            (unsigned long) first_value > (unsigned long) end_value ||
            end_ptr == string_check_ptr)
        {
            return ERR_INVALID_ARGUMENT;
        }

        // set all bits in range to 1
        for(; (unsigned long) first_value <= (unsigned long) end_value; first_value++) {
            ADD_TO_ARR(arr, first_value);
            (*count)++;
        }
        return ERR_SUCCESS;
    }   // range of ports 

    // multiple ports a, b, c
    if (*string_check_ptr == ',') {
        // not proud of this
        char* str = string_check_ptr + 1;
        ADD_TO_ARR(arr, first_value);
        *count += 1U;

        // loop thorough all all ports that are separated by `,`
        while(1) {
            first_value = strtol(str, &string_check_ptr, NUMBER_SYSTEM);

            // strtol errors check
            if(errno != 0 || 
                first_value < 0 || 
                first_value > MAX_PORTS || 
                string_check_ptr == str) 
            {
                return ERR_INVALID_ARGUMENT;
            }
            // add to array (0 if strtol failed)
            ADD_TO_ARR(arr, first_value);
            (*count)++;

            if(*string_check_ptr == '\0') {
                return ERR_SUCCESS;
            }
            // strtol error 
            if(*string_check_ptr != ',') {
                return ERR_INVALID_ARGUMENT;
            }

            str = string_check_ptr + 1;
        }
    }
    return ERR_FAILURE;
}   // convert_str_to_nums

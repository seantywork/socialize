#include "rat-chat/cli/cli.h"
#include "rat-chat/utils.h"



int main(int argc, char **argv){



    if(argc == 1){

        run_cli();


    } else {

        if(strcmp(argv[1], "1") == 0){


            run_cli_test(1);

        } else if (strcmp(argv[1], "2") == 0){

            run_cli_test(2);

        } else {

            printf("wrong argument: %s\n", argv[1]);

            return -1;

        }

    }

    return 0;
}
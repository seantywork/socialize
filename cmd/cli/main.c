#include "chat/cli/cli.h"
#include "chat/utils.h"

int cli_done = 0;
int TEST_CASE = -1;


static void signal_handler(int sig){


    cli_done = 1;

}

int main(int argc, char **argv){


    if(argc < 2){
        printf("feed arguments\n");
        printf("addr, or addr + number\n");

        return -1;
    }


    signal(SIGINT, signal_handler);

    if(argc == 2){

        run_cli(argv[1]);


    } else {

        if(strcmp(argv[2], "1") == 0){

            TEST_CASE = 1;

            run_cli(argv[1]);

        } else if (strcmp(argv[2], "2") == 0){

            TEST_CASE = 2;

            run_cli(argv[1]);

        } else {

            printf("wrong argument: %s\n", argv[2]);

            return -1;

        }

    }

    return 0;
}
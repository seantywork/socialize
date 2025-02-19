

GCC_DEV_FLAGS := -Wall -g

GCC_REL_FLAGS := -Wall

GCC_OBJ_FLAGS := -Wall -c

DEP_PACKAGES := libssl-dev

DEP_MONGOOSE := git clone https://github.com/seantywork/mongoose.git

DEP_CJSON := git clone https://github.com/seantywork/cJSON.git

INCLUDES := -I./include -I./vendor

LIBS := -lpthread -lssl -lcrypto 


OBJS := ctl.o
OBJS += utils.o
OBJS += sock.o
OBJS += front.o

CLI_OBJS := cli.o
CLI_OBJS += utils.o

DEP_OBJS := mongoose.o
DEP_OBJS += cJSON.o


all: 

	@echo "rat-chat: dev, release"


deps:

	apt-get update

	apt-get -y install $(DEP_PACKAGES)

.PHONY: vendor
vendor:

	cd vendor && rm -rf mongoose && $(DEP_MONGOOSE)

	cd vendor && rm -rf cJSON && $(DEP_CJSON)


dev: $(OBJS) $(CLI_OBJS) $(DEP_OBJS)

	gcc $(GCC_DEV_FLAGS) $(INCLUDES) -o engine.out cmd/engine/main.c $(OBJS) $(DEP_OBJS) $(LIBS) 

	gcc $(GCC_DEV_FLAGS) $(INCLUDES) -o cli.out cmd/cli/main.c $(CLI_OBJS) $(LIBS) 




release: $(OBJS) $(DEP_OBJS)

	gcc $(GCC_REL_FLAGS) $(INCLUDES) -o engine.out cmd/engine/main.c $(OBJS) $(DEP_OBJS) $(LIBS) 

	gcc $(GCC_REL_FLAGS) $(INCLUDES) -o cli.out cmd/cli/main.c $(CLI_OBJS) $(LIBS) 



ctl.o:

	gcc $(GCC_OBJ_FLAGS) $(INCLUDES) -o ctl.o src/ctl.c 


utils.o:

	gcc $(GCC_OBJ_FLAGS) $(INCLUDES) -o utils.o src/utils.c 

sock.o:

	gcc $(GCC_OBJ_FLAGS) $(INCLUDES) -o sock.o src/sock/sock.c 

front.o:

	gcc $(GCC_OBJ_FLAGS) $(INCLUDES) -o front.o src/front/front.c 


cli.o:

	gcc $(GCC_OBJ_FLAGS) $(INCLUDES) -o cli.o src/cli/cli.c 



mongoose.o:


	gcc $(GCC_OBJ_FLAGS) $(INCLUDES) -o mongoose.o vendor/mongoose/mongoose.c 

cJSON.o:

	gcc $(GCC_OBJ_FLAGS) $(INCLUDES) -o cJSON.o vendor/cJSON/cJSON.c 




clean:

	rm -rf *.o *.out *.txt


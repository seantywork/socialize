

GCC_DEV_FLAGS := -Wall -g

GCC_REL_FLAGS := -Wall

GCC_OBJ_FLAGS := -Wall -c

DEP_PACKAGES := libssl-dev

DEP_MONGOOSE := git clone https://github.com/seantywork/mongoose.git

DEP_CJSON := git clone https://github.com/seantywork/cJSON.git

INCLUDES := -I./include -I./vendor

LIBS := -lpthread -lssl -lcrypto 


OBJS := core.o
OBJS += utils.o
OBJS += sock.o
OBJS += front.o

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


dev: $(OBJS) $(DEP_OBJS)

	gcc $(GCC_DEV_FLAGS) $(INCLUDES) -o rat-chat.out cmd/rat-chat/main.c $(OBJS) $(DEP_OBJS) $(LIBS) 


release: $(OBJS) $(DEP_OBJS)

	gcc $(GCC_REL_FLAGS) $(INCLUDES) -o rat-chat.out cmd/rat-chat/main.c $(OBJS) $(DEP_OBJS) $(LIBS) 




core.o:

	gcc $(GCC_OBJ_FLAGS) $(INCLUDES) -o core.o src/core.c 


utils.o:

	gcc $(GCC_OBJ_FLAGS) $(INCLUDES) -o utils.o src/utils.c 

sock.o:

	gcc $(GCC_OBJ_FLAGS) $(INCLUDES) -o sock.o src/hubsock/core.c 

front.o:

	gcc $(GCC_OBJ_FLAGS) $(INCLUDES) -o front.o src/hubfront/core.c 


mongoose.o:


	gcc $(GCC_OBJ_FLAGS) $(INCLUDES) -o mongoose.o vendor/mongoose/mongoose.c 

cJSON.o:

	gcc $(GCC_OBJ_FLAGS) $(INCLUDES) -o cJSON.o vendor/cJSON/cJSON.c 




clean:

	rm -rf *.o *.out *.txt



#include "rat-chat/sock/core.h"
#include "rat-chat/front/core.h"

#include "rat-chat/utils.h"
FILE* LOGFP;

pthread_mutex_t G_MTX;

int main(){


  srand((unsigned int)time(NULL));

  LOGFP = fopen("log.txt","a");


  pthread_t sock_tid;
  pthread_t front_tid;

  if (pthread_mutex_init(&G_MTX, NULL) != 0) { 
      printf("mutex init has failed\n"); 
      return -1; 
  } 


  pthread_create(&front_tid, NULL, (void*)front_listen_and_serve, NULL);

  sleepms(500);

  pthread_create(&sock_tid, NULL, (void*)sock_listen_and_serve, NULL);

  sleepms(500);


  pthread_join(front_tid, NULL);

  fclose(LOGFP);


}
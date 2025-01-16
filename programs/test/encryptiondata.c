#include "encryptiondata.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/timeb.h>

unsigned char tmptest[200];
unsigned char buftest[BUFSIZE];

void set_array(void){
memset(buftest, 0xAA, sizeof(buftest));
memset(tmptest, 0xBB, sizeof(tmptest));
}

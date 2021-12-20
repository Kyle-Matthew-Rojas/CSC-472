/*
Final Project for CSC 472/583 2021 Fall
*/

#include <stdio.h>
#include <stdlib.h>

char buf[1048];

int calendar(){
    puts("cal");
    read(0, buf, 100);
}

int loop() {
  char str[100];
  if(!gets(str)) return 0;
  snprintf(buf, sizeof(buf), str);
  write(1, buf, strlen(buf));
  return 1;
}

void main() {
  while(loop());
  exit(0);
}

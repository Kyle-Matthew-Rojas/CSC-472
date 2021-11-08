#include <stdio.h>
#include <string.h>

char string[100];

void exec_string(int a) {
  if (a == 0xabcdabcd) {
        system(string);
    }
}

void add_bin(int arg1, int arg2, int arg3) {
  if (arg1 == 0xff424242 && arg2 == 0xffff4141 && arg3 == 0xdeadbeef) {
    strcat(string, "/bin");
  }
}

void add_bash(int magic1, int magic2) {
  if (magic1 == 0xcafebabe && magic2 == 0xffffffff) {
    strcat(string, "/bash");
  }
}

void vulnerable_function(char *string) {
  char buffer[140];
  gets(buffer);
}

int main(int argc, char** argv) {
  string[0] = 0;
  vulnerable_function(argv[1]);
  return 0;
}

#include <unistd.h>
#include <stdio.h>

void vuln() {
    char buffer[25];
    read(0, buffer, 100);
    puts(buffer);
    write(1, buffer, 25);
}

int main() {
    vuln();
}

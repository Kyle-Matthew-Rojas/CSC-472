#include <stdio.h>
int add_plus1(int a, int b)
{
    int x = a;
    int y = b;
    return x+y+1;
}

int main(int argc, char** argv) {
    int a=5, b=6;
    int d = add_plus1(a,b);
    printf("%d\n", d);
    return 0;
}

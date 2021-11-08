#include <stdio.h>
#include <string.h>

void hacked()
{
        /* change YOURNAME to your name :) */
        puts("Hacked by Kyle Matthew Rojas!!!!");
}

void return_input(void)
{
        /* Please set the array size equal to 
         the last two digits of your student ID
         e.g. 0861339 --> array size should set to 39 */
        char array[29];  
        gets(array);
        printf("%s\n", array);
}

main()
{
        return_input();
        return 0;
}

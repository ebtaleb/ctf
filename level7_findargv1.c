int main(int argc, const char *argv[])
{
    int derp = -2;
    unsigned int target = 60;

    while (1) {
        if ( ((unsigned int)derp * 4) == target) {
            break;
        }

        if (derp == -1) {
            return -1;
        }

        derp--;

    }
    printf("%d\n", derp);
    return 0;
}

#include <cstdio>
#include <sys/signal.h>
#include <unistd.h>
int main() {
    unsigned long long a = 0xcafecafe;
    auto a_address = &a;
    write(STDOUT_FILENO, &a_address, sizeof(void*));
    fflush(stdout);
    raise(SIGTRAP);
}
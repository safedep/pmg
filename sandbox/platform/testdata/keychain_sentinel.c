#include <sys/types.h>
#include <sys/sysctl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    size_t size = 0;
    if (sysctlbyname("security.mac.sandbox.sentinel", NULL, &size, NULL, 0)) {
        int error = errno;
        perror("sentinel size");
        return error == ENOENT ? 2 : 1;
    }
    void *value = malloc(size);
    if (!value) return 3;
    int result = sysctlbyname("security.mac.sandbox.sentinel", value, &size, NULL, 0);
    int error = errno;
    free(value);
    if (!result) return 0;
    errno = error;
    perror("sentinel read");
    return error == ENOENT ? 2 : 1;
}

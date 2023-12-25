#include <stdio.h>

int main() {
    FILE *maps_file = fopen("/proc/self/maps", "r");
    if (maps_file == NULL) {
        perror("Error opening /proc/self/maps");
        return 1;
    }

    char line[256];
    while (fgets(line, sizeof(line), maps_file) != NULL) {
        printf("%s", line);
    }

    fclose(maps_file);
    return 0;
}
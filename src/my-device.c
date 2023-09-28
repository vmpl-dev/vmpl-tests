#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "my-device.h"

int test_ioctl_example() {
    int fd = open(MY_DEVICE_FILE_NAME, O_RDWR);
    if (fd < 0) {
        perror("Failed to open the device file");
        return 1;
    }

    // Example usage of MY_IOCTL_CMD1
    struct my_ioctl_data1 cmd1_data;
    cmd1_data.value1 = 10;
    cmd1_data.value2 = 20;
    cmd1_data.value3 = 'A';
    if (ioctl(fd, MY_IOCTL_CMD1, &cmd1_data) < 0) {
        perror("Failed to send ioctl command 1");
        close(fd);
        return 1;
    }

    // Example usage of MY_IOCTL_CMD2
    struct my_ioctl_data2 cmd2_data;
    cmd2_data.value1 = 30;
    cmd2_data.value2 = 40;
    if (ioctl(fd, MY_IOCTL_CMD2, &cmd2_data) < 0) {
        perror("Failed to send ioctl command 2");
        close(fd);
        return 1;
    }

    // Example usage of MY_IOCTL_CMD3
    struct my_ioctl_data3 cmd3_data;
    cmd3_data.value1 = 50;
    if (ioctl(fd, MY_IOCTL_CMD3, &cmd3_data) < 0) {
        perror("Failed to send ioctl command 3");
        close(fd);
        return 1;
    }

    close(fd);
    return 0;
}
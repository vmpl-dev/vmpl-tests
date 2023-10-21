#ifndef __ARGS_H_
#define __ARGS_H_

struct arguments {
    int init;
    int enter;
};

void parse_args(int argc, char *argv[], struct arguments *arguments);

#endif
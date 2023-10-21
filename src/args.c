#include <argp.h>

#include "args.h"

const char *argp_program_version = "1.0";
const char *argp_program_bug_address = "<your-email@example.com>";
/* Program documentation. */
static char doc[] = "ARGP Example - A simple ARGP program.";
/* A description of the arguments we accept. */
static char args_doc[] = "";

static struct argp_option options[] = {
    {"init", 'i', 0, 0, "Init the game", 0},
    {"enter", 'e', 0, 0, "Enter the game", 0},
    {0}
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;

    switch (key) {
        case 'e':
            arguments->enter = 1;
            break;
        case 'i':
            arguments->init = 1;
            break;
        case ARGP_KEY_ARG:
            if (state->arg_num > 3) {
                /* Too many arguments. */
                printf("Too many arguments.\n");
                argp_usage(state);
            }
            break;
        case ARGP_KEY_END:
            if (state->arg_num < 0)
            /* Not enough arguments. */
            argp_usage(state);
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static struct argp argp = {options, parse_opt, args_doc, doc};

void parse_args(int argc, char *argv[], struct arguments *arguments)
{
    argp_parse(&argp, argc, argv, 0, 0, arguments);
}
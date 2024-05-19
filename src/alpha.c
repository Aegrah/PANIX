#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

// Function prototypes for tasks
void write_file();
void read_file();
void list_processes();
void show_uptime();
void show_options(int is_root);
void handle_command(int is_root, int argc, char *argv[]);
void print_banner();

// Error handling function
void handle_error(const char *message) {
    perror(message);
    exit(EXIT_FAILURE);
}

// Write "foo" to /tmp/foo.txt
void write_file() {
    FILE *file = fopen("/tmp/foo.txt", "w");
    if (file == NULL) {
        handle_error("Error opening file for writing");
    }

    if (fprintf(file, "foo") < 0) {
        fclose(file);
        handle_error("Error writing to file");
    }

    if (fclose(file) != 0) {
        handle_error("Error closing file after writing");
    }

    printf("Successfully wrote to /tmp/foo.txt\n");
}

// whoami
void whoami() {
    system("whoami");
}

// id
void id() {
    system("id");
}

// List running processes
void list_processes() {
    system("ps aux");
}

// Show system uptime
void show_uptime() {
    system("uptime");
}

// Struct to hold command information
typedef struct {
    const char *long_opt;
    const char *short_opt;
    const char *description;
    void (*func)();
} Command;

// Define command options
Command root_commands[] = {
    {"--whoami", "-w", "whoami", whoami},
    {"--list_processes", "-l", "List running processes", list_processes},
    {NULL, NULL, NULL, NULL} // Sentinel to mark the end of the array
};

Command user_commands[] = {
    {"--id", "-i", "id", id},
    {"--show_uptime", "-u", "Show system uptime", show_uptime},
    {NULL, NULL, NULL, NULL} // Sentinel to mark the end of the array
};

// Show available options based on user privileges
void show_options(int is_root) {
    Command *commands = is_root ? root_commands : user_commands;
    printf("Running with %s privileges. Available commands:\n", is_root ? "root" : "non-root");
    for (int i = 0; commands[i].long_opt != NULL; i++) {
        if (commands[i].short_opt != NULL) {
            printf("%-20s %-4s : %s\n", commands[i].long_opt, commands[i].short_opt, commands[i].description);
        } else {
            printf("%-20s %-4s : %s\n", commands[i].long_opt, "", commands[i].description);
        }
    }
}

// Handle the command based on user privileges
void handle_command(int is_root, int argc, char *argv[]) {
    Command *commands = is_root ? root_commands : user_commands;
    int i;
    for (i = 1; i < argc; i++) {
        int found = 0;
        for (int j = 0; commands[j].long_opt != NULL; j++) {
            if (strcmp(argv[i], commands[j].long_opt) == 0 || 
                (commands[j].short_opt != NULL && strcmp(argv[i], commands[j].short_opt) == 0)) {
                if (commands[j].func != NULL) {
                    commands[j].func();
                    found = 1;
                    break;
                }
            }
        }
        if (!found) {
            fprintf(stderr, "Invalid option for %s user: %s\n", is_root ? "root" : "non-root", argv[i]);
            show_options(is_root);
            exit(EXIT_FAILURE);
        }
    }
    if (i == 1) { // No command specified
        print_banner();
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


int main(int argc, char *argv[]) {
    int is_root = (geteuid() == 0);

    if (argc == 1) {
        print_banner();
        show_options(is_root);
    } else {
        handle_command(is_root, argc, argv);
    }

    return EXIT_SUCCESS;
}

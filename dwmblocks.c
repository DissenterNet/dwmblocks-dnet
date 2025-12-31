/*
 * dwmblocks.c
 *
 * - Periodically runs configured shell commands ("blocks") and assembles their outputs
 *   into a single status string.
 * - Publishes the status either by setting the X root window name (X11) or printing to stdout.
 * - Supports interval-based updates and per-block on-demand updates driven by realtime signals.
 * - Supports "button" events delivered via SIGUSR1 with a sigqueue payload. Button events are
 *   exposed to block commands using the BUTTON environment variable for that invocation.
 *
 * Implementation highlights:
 * - Signal handlers perform only async-signal-safe writes to a self-pipe; the main loop polls
 *   the pipe and performs the heavy work (popen, string ops, X calls).
 * - Uses sigaction to register handlers and SA_SIGINFO for SIGUSR1 (to receive payload).
 */

#define _POSIX_C_SOURCE 200809L /* for sigaction, sigemptyset, pipe, poll, etc. */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>     /* fcntl, O_NONBLOCK, FD_CLOEXEC */
#include <poll.h>      /* poll(), struct pollfd */
#include <errno.h>
#include <stdint.h>

#ifndef NO_X
#include <X11/Xlib.h>
#endif

/* Portability mapping for realtime signal base */
#ifdef __OpenBSD__
#define SIGPLUS   SIGUSR1+1
#define SIGMINUS  SIGUSR1-1
#else
#define SIGPLUS   SIGRTMIN
#define SIGMINUS  SIGRTMIN
#endif

/* Helper macros */
#define LENGTH(X)      (sizeof(X) / sizeof (X[0]))
#define CMDLENGTH      50
#define MIN(a,b)       ((a) < (b) ? (a) : (b))

/* NOTE: STATUSLENGTH depends on LENGTH(blocks). blocks[] is defined in blocks.h */
#define STATUSLENGTH   (LENGTH(blocks) * CMDLENGTH + 1)

/* Block definition (from blocks.h) - kept here for clarity */
typedef struct {
    char *icon;            /* prefix text for display */
    char *command;         /* shell command to run */
    unsigned int interval; /* seconds between automatic updates (0 = never) */
    unsigned int signal;   /* numeric signal id (mapped to SIGMINUS + signal) */
} Block;

/* Forward declarations for functions */
#ifndef __OpenBSD__
void dummysighandler(int num);
#endif
void sighandler(int signum);                            /* realtime signal handler (writes to pipe) */
void buttonhandler(int sig, siginfo_t *si, void *ucontext); /* SIGUSR1 handler (writes to pipe) */
void termhandler(int signum);                           /* SIGTERM/SIGINT handler (sets flag) */

void getcmds(int time);         /* update interval-driven blocks */
void getsigcmds(unsigned int signal); /* update signal-driven blocks */
void setupsignals(void);        /* install handlers, create self-pipe */

int getstatus(char *str, char *last); /* assemble status string and detect change */
void statusloop(void);          /* main loop */
void pstdout(void);             /* writer to stdout */

#ifndef NO_X
void setroot(void);
static int setupX(void);
static Display *dpy;
static int screen;
static Window root;
#endif

/* Include user config which defines blocks[], delim[], delimLen */
#include "blocks.h"

/* Per-block status buffers */
static char statusbar[LENGTH(blocks)][CMDLENGTH] = {0};
/* Double-buffered assembled status */
static char statusstr[2][STATUSLENGTH];

/* Transient BUTTON char: if non-NUL, it will be exported to the invoked command as env var BUTTON */
static char button[] = "\0";

/* Self-pipe for safe signal handling.
 * Handlers write events into sigpipe[1]; main loop reads sigpipe[0].
 */
static int sigpipe[2] = { -1, -1 };

/* Control flags */
static volatile sig_atomic_t statusContinue = 1;
static int returnStatus = 0;

/* Writer pointer: either setroot (X) or pstdout (stdout) */
#ifndef NO_X
static void (*writestatus)(void) = setroot;
#else
static void (*writestatus)(void) = pstdout;
#endif

/* ------------------------ Implementation ------------------------ */

/**
 * @brief Execute a block command and capture its output into the provided buffer
 * @param block Pointer to Block structure containing command configuration
 * @param output Buffer to store the command output and any signal encoding
 * @return void
 * 
 * This function executes a shell command using popen() and captures its output.
 * If the block has a signal configured, the first byte of the output buffer
 * is set to the signal value (legacy compact encoding), followed by the icon
 * and command output.
 * 
 * Handles button events by setting BUTTON environment variable for the command
 * if a button click is pending, then clears the button state.
 * 
 * @warning SECURITY: Command injection vulnerability through popen() - block commands
 *          should be validated and come from trusted sources
 * @warning PERFORMANCE: Uses popen() which spawns a shell process for each block
 * @warning MEMORY: Potential buffer overflow if command output exceeds CMDLENGTH
 * @bug ERROR HANDLING: No proper error checking for popen() failure
 * @bug RACE CONDITION: Button variable access is not thread-safe
 * 
 */
void getcmd(const Block *block, char *output)
{
    if (block->signal) {
        output[0] = (char)block->signal;
        output++;
    }

    /* Copy icon prefix */
    strcpy(output, block->icon);

    FILE *cmdf = NULL;

    if (*button) {
        /* Expose the pending BUTTON to the child command; then clear it */
        setenv("BUTTON", button, 1);
        cmdf = popen(block->command, "r");
        *button = '\0';
        unsetenv("BUTTON");
    } else {
        cmdf = popen(block->command, "r");
    }

    if (!cmdf)
        return;

    int i = strlen(block->icon);

    if (CMDLENGTH - i - (int)delimLen > 0)
        fgets(output + i, CMDLENGTH - i - delimLen, cmdf);
    else
        output[i] = '\0';

    i = strlen(output);
    if (i != 0) {
        i = (output[i - 1] == '\n') ? i - 1 : i;
        if (delim[0] != '\0') {
            strncpy(output + i, delim, delimLen);
        } else {
            output[i] = '\0';
            i++;
        }
    }

    pclose(cmdf);
}

/**
 * @brief Update blocks that are configured for interval-based updates
 * @param time Current tick counter value, -1 forces update of all blocks
 * 
 * This function iterates through all configured blocks and updates those
 * that have interval-based timing configured. A block is updated when:
 * - Its interval is non-zero AND current time modulo interval equals zero
 * - OR when time is -1 (force update all blocks)
 * 
 * @note Time is typically incremented each second by the main loop
 * @warning PERFORMANCE: Iterates through all blocks on every call
 * @bug LOGIC: No validation of time parameter bounds
 * 
 * @return void
 */
void getcmds(int time)
{
    const Block *current;
    for (unsigned int i = 0; i < LENGTH(blocks); i++) {
        current = &blocks[i];
        if ((current->interval != 0 && time % current->interval == 0) || time == -1)
            getcmd(current, statusbar[i]);
    }
}

/* getsigcmds: run blocks matching the given signal id */
void getsigcmds(unsigned int signal)
{
    const Block *current;
    for (unsigned int i = 0; i < LENGTH(blocks); i++) {
        current = &blocks[i];
        if (current->signal == signal)
            getcmd(current, statusbar[i]);
    }
}

/**
 * @brief Initialize signal handling infrastructure for dwmblocks
 * 
 * This function sets up the complete signal handling system including:
 * - Self-pipe creation for async-signal-safe communication
 * - Real-time signal handlers for each block's configured signal
 * - Button click handler with SA_SIGINFO for payload reception
 * - Termination handlers for graceful shutdown
 * 
 * @warning COMPLEXITY: This function performs multiple critical operations
 *          and any failure could leave system in inconsistent state
 * @warning SECURITY: Signal handlers can be exploited for code execution
 * @warning PERFORMANCE: Multiple sigaction() calls may impact startup time
 * @bug ERROR HANDLING: Partial failure handling could leave signals unhandled
 * @bug RESOURCE LEAK: If pipe() fails after some sigactions are set
 * 
 * @note Uses sigaction() instead of signal() for better control
 * @note Self-pipe pattern avoids async-signal-safe restrictions
 * @note SA_SIGINFO enables sigqueue payload reception
 * 
 * @return void
 */
void setupsignals(void)
{
#ifndef __OpenBSD__
    /* Register dummy handler for all RT signals to avoid default behavior */
    for (int s = SIGRTMIN; s <= SIGRTMAX; s++) {
        struct sigaction sa_dummy;
        memset(&sa_dummy, 0, sizeof(sa_dummy));
        sa_dummy.sa_handler = dummysighandler;
        sigemptyset(&sa_dummy.sa_mask);
        sa_dummy.sa_flags = 0;
        sigaction(s, &sa_dummy, NULL);
    }
#endif

    /* Create the self-pipe for event transport if not already created */
    if (sigpipe[0] == -1) {
        if (pipe(sigpipe) == -1) {
            fprintf(stderr, "dwmblocks: pipe() failed: %s\n", strerror(errno));
        } else {
            /* set read end non-blocking so reads in main loop don't block */
            int flags = fcntl(sigpipe[0], F_GETFL, 0);
            if (flags != -1)
                fcntl(sigpipe[0], F_SETFL, flags | O_NONBLOCK);
            /* set close-on-exec to avoid leaking pipe fds to children */
            flags = fcntl(sigpipe[0], F_GETFD, 0);
            if (flags != -1)
                fcntl(sigpipe[0], F_SETFD, flags | FD_CLOEXEC);
            flags = fcntl(sigpipe[1], F_GETFD, 0);
            if (flags != -1)
                fcntl(sigpipe[1], F_SETFD, flags | FD_CLOEXEC);
        }
    }

    /* Build mask for button handler to block RT signals while handling SIGUSR1 */
    struct sigaction sa_button;
    memset(&sa_button, 0, sizeof(sa_button));
    sigemptyset(&sa_button.sa_mask);

    /* Register RT signal handlers for blocks and add them to sa_button mask */
    for (unsigned int i = 0; i < LENGTH(blocks); i++) {
        if (blocks[i].signal > 0) {
            struct sigaction sa_rt;
            memset(&sa_rt, 0, sizeof(sa_rt));
            sa_rt.sa_handler = sighandler;
            sigemptyset(&sa_rt.sa_mask);
            sa_rt.sa_flags = 0;
            sigaction(SIGMINUS + blocks[i].signal, &sa_rt, NULL);

            /* Block this RT signal while executing buttonhandler */
            sigaddset(&sa_button.sa_mask, SIGMINUS + blocks[i].signal);
        }
    }

    /* Install buttonhandler for SIGUSR1 (uses SA_SIGINFO to receive payload) */
    sa_button.sa_sigaction = buttonhandler;
    sa_button.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR1, &sa_button, NULL);

    /* Install termhandler for SIGTERM and SIGINT using sigaction */
    {
        struct sigaction sa_term;
        memset(&sa_term, 0, sizeof(sa_term));
        sa_term.sa_handler = termhandler;
        sigemptyset(&sa_term.sa_mask);
        sa_term.sa_flags = 0;
        sigaction(SIGTERM, &sa_term, NULL);
        sigaction(SIGINT, &sa_term, NULL);
    }
}

/* getstatus:
 * Assemble all per-block strings into a single status string and remove trailing delim.
 * Return non-zero if the assembled string differs from last (i.e., changed).
 */
int getstatus(char *str, char *last)
{
    strcpy(last, str);
    str[0] = '\0';

    for (unsigned int i = 0; i < LENGTH(blocks); i++)
        strcat(str, statusbar[i]);

    size_t slen = strlen(str);
    size_t dlen = strlen(delim);
    if (slen >= dlen && dlen > 0)
        str[slen - dlen] = '\0';
    else
        str[0] = '\0';

    return strcmp(str, last);
}

#ifndef NO_X
/* setroot: publish status to X root window name */
void setroot(void)
{
    if (!getstatus(statusstr[0], statusstr[1]))
        return;
    XStoreName(dpy, root, statusstr[0]);
    XFlush(dpy);
}

/* setupX: open X display and set global root window */
static int setupX(void)
{
    dpy = XOpenDisplay(NULL);
    if (!dpy) {
        fprintf(stderr, "dwmblocks: Failed to open display\n");
        return 0;
    }
    screen = DefaultScreen(dpy);
    root = RootWindow(dpy, screen);
    return 1;
}
#endif

/* pstdout: print status to stdout when it changes */
void pstdout(void)
{
    if (!getstatus(statusstr[0], statusstr[1]))
        return;
    printf("%s\n", statusstr[0]);
    fflush(stdout);
}

/**
 * @brief Main event loop for dwmblocks status bar system
 * 
 * This function implements the core event-driven architecture:
 * 1. Initializes signal handling infrastructure
 * 2. Performs initial block population
 * 3. Enters infinite loop processing interval updates and signal events
 * 
 * Event encoding protocol:
 * - 'R' <signal-id-byte> : Realtime signal event
 * - 'B' <button-byte> <signal-id-byte> : Button click event
 * 
 * @warning CRITICAL: This function has multiple security vulnerabilities:
 *          - Command injection through block commands
 *          - Environment variable injection via BUTTON
 *          - Unsafe signal handling with race conditions
 * @warning PERFORMANCE: Inefficient string concatenation in getstatus()
 * @warning MEMORY: Static buffers may be oversized, potential overflows
 * @warning THREAD SAFETY: Global variables accessed without synchronization
 * 
 * @bug SECURITY: Block commands executed via popen() without validation
 * @bug RACE CONDITION: Signal handlers and main loop share button variable
 * @bug RESOURCE LEAK: File descriptors may not be closed on all error paths
 * 
 * @note Uses self-pipe pattern for async-signal-safe communication
 * @note Implements double-buffering to avoid status flicker
 * 
 * @return void (exits via returnStatus global)
 */
void statusloop(void)
{
    setupsignals();

    int i = 0;
    getcmds(-1); /* initial fill */

    struct pollfd pfd;
    pfd.fd = (sigpipe[0] != -1) ? sigpipe[0] : -1;
    pfd.events = POLLIN;

    while (1) {
        /* Interval-driven updates */
        getcmds(i++);

        if (pfd.fd != -1) {
            int ret = poll(&pfd, 1, 1000); /* 1 second timeout */
            if (ret > 0 && (pfd.revents & POLLIN)) {
                unsigned char buf[256];
                ssize_t n = read(pfd.fd, buf, sizeof(buf));
                if (n > 0) {
                    for (ssize_t off = 0; off < n; ) {
                        unsigned char t = buf[off++];
                        if (t == (unsigned char)'R') {
                            if (off < n) {
                                unsigned int sigid = (unsigned int)buf[off++];
                                getsigcmds(sigid);
                            } else {
                                break;
                            }
                        } else if (t == (unsigned char)'B') {
                            if (off + 1 < n) {
                                unsigned char low = buf[off++];
                                unsigned char high = buf[off++];
                                *button = (char)('0' + (low & 0xff));
                                getsigcmds((unsigned int)high);
                            } else {
                                break;
                            }
                        } else {
                            /* Unknown token: stop parsing */
                            break;
                        }
                    }
                }
            }
        } else {
            /* If pipe isn't available, fallback to sleeping */
            sleep(1);
        }

        /* Publish the status (writers check for actual changes) */
        writestatus();

        if (!statusContinue)
            break;
    }
}

/* dummysighandler: no-op handler for initializing RT signals */
#ifndef __OpenBSD__
void dummysighandler(int signum)
{
    (void)signum;
}
#endif

/* buttonhandler (SIGUSR1):
 * - Receives siginfo_t payload (via sigqueue) with sival_int encoded as:
 *     low byte: button id, high bytes: signal id
 * - Writes an event into the self-pipe. This is async-signal-safe.
 */
void buttonhandler(int sig, siginfo_t *si, void *ucontext)
{
    (void)sig;
    (void)ucontext;
    if (sigpipe[1] != -1) {
        unsigned char buf[3];
        buf[0] = (unsigned char)'B';
        buf[1] = (unsigned char)(si->si_value.sival_int & 0xff);
        buf[2] = (unsigned char)((si->si_value.sival_int >> 8) & 0xff);
        /* write is async-signal-safe; ignore return value */
        (void)write(sigpipe[1], buf, sizeof(buf));
    }
}

/* sighandler (realtime signals):
 * - Encodes 'R' event and the signal id byte into the self-pipe.
 */
void sighandler(int signum)
{
    if (sigpipe[1] != -1) {
        unsigned char buf[2];
        buf[0] = (unsigned char)'R';
        buf[1] = (unsigned char)((signum - SIGPLUS) & 0xff);
        (void)write(sigpipe[1], buf, sizeof(buf));
    }
}

/* termhandler: set the volatile flag to request shutdown of main loop */
void termhandler(int signum)
{
    (void)signum;
    statusContinue = 0;
}

/* main: parse -d and -p options, init X (if compiled with X), set delimLen, and enter loop */
int main(int argc, char **argv)
{
    for (int i = 0; i < argc; i++) {
        if (!strcmp("-d", argv[i])) {
            strncpy(delim, argv[++i], delimLen);
        } else if (!strcmp("-p", argv[i])) {
            writestatus = pstdout;
        }
    }

#ifndef NO_X
    if (!setupX())
        return 1;
#endif

    delimLen = MIN(delimLen, strlen(delim));
    delim[delimLen++] = '\0';

    statusloop();

#ifndef NO_X
    XCloseDisplay(dpy);
#endif

    return returnStatus;
}

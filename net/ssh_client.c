#include "ssh_client.h"
#include <libssh2.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

int ssh_run_command(const char *host, const char *user, const char *pass, const char *cmd) {
    int rc;
    LIBSSH2_SESSION *session = NULL;
    LIBSSH2_CHANNEL *channel = NULL;
    int sock = -1;
    struct sockaddr_in sin;

    // Start up libssh2
    rc = libssh2_init(0);
    if (rc != 0) {
        fprintf(stderr, "libssh2 initialization failed (%d)\n", rc);
        return 1;
    }

    // Resolve hostname
    struct hostent *he = gethostbyname(host);
    if (!he) {
        fprintf(stderr, "Could not resolve host: %s\n", host);
        return 1;
    }

    // Create socket and connect
    sock = socket(AF_INET, SOCK_STREAM, 0);
    sin.sin_family = AF_INET;
    sin.sin_port = htons(22);
    sin.sin_addr = *((struct in_addr *)he->h_addr);
    if (connect(sock, (struct sockaddr *)(&sin), sizeof(struct sockaddr_in)) != 0) {
        fprintf(stderr, "Failed to connect to %s\n", host);
        goto cleanup;
    }

    // Create session
    session = libssh2_session_init();
    if (!session) {
        fprintf(stderr, "Could not initialize SSH session\n");
        goto cleanup;
    }

    libssh2_session_set_blocking(session, 1);

    rc = libssh2_session_handshake(session, sock);
    if (rc) {
        fprintf(stderr, "SSH session handshake failed: %d\n", rc);
        goto cleanup;
    }

    // Authenticate
    rc = libssh2_userauth_password(session, user, pass);
    if (rc) {
        fprintf(stderr, "Authentication failed for %s\n", user);
        goto cleanup;
    }

    // Open channel and run command
    channel = libssh2_channel_open_session(session);
    if (!channel) {
        fprintf(stderr, "Could not open channel\n");
        goto cleanup;
    }

    rc = libssh2_channel_exec(channel, cmd);
    if (rc) {
        fprintf(stderr, "Command execution failed: %d\n", rc);
        goto cleanup;
    }

    // Read output
    char buffer[1024];
    ssize_t bytes_read;
    while ((bytes_read = libssh2_channel_read(channel, buffer, sizeof(buffer))) > 0) {
        fwrite(buffer, 1, bytes_read, stdout);
    }

    libssh2_channel_close(channel);

cleanup:
    if (channel)
        libssh2_channel_free(channel);
    if (session) {
        libssh2_session_disconnect(session, "Goodbye");
        libssh2_session_free(session);
    }
    if (sock != -1)
        close(sock);
    libssh2_exit();
    return 0;
}

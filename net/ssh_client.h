#ifndef GHOSTSHELL_SSH_CLIENT_H
#define GHOSTSHELL_SSH_CLIENT_H

// Basic SSH command execution
// Returns 0 on success, non-zero on error
int ssh_run_command(const char *host, const char *user, const char *pass, const char *cmd);

#endif // GHOSTSHELL_SSH_CLIENT_H

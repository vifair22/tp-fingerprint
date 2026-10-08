/*
 * pamcheck: run one PAM authentication from a service file in a directory
 * of our choosing, so pam_fpd.so can be tried end to end, against the real
 * fpd, without touching /etc/pam.d.
 *
 *   pamcheck CONFDIR SERVICE USER
 *
 * Prints what the modules say and the outcome; exits 0 only on success.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <security/pam_appl.h>

/* Shows informational and error messages; answers prompts with nothing, so
 * a stack that asks for a password simply fails. */
static int conv(int n, const struct pam_message **msg, struct pam_response **resp, void *data)
{
    (void)data;
    if (n <= 0)
        return PAM_CONV_ERR;
    struct pam_response *r = calloc((size_t)n, sizeof *r);
    if (r == NULL)
        return PAM_BUF_ERR;
    for (int i = 0; i < n; i++) {
        const char *kind = "?";
        switch (msg[i]->msg_style) {
        case PAM_TEXT_INFO:
            kind = "info";
            break;
        case PAM_ERROR_MSG:
            kind = "error";
            break;
        default:
            kind = "prompt";
            break;
        }
        printf("pam %s: %s\n", kind, msg[i]->msg);
    }
    (void)fflush(stdout);
    *resp = r;
    return PAM_SUCCESS;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        (void)fprintf(stderr, "usage: pamcheck CONFDIR SERVICE USER\n");
        return 2;
    }
    const struct pam_conv c = {conv, NULL};
    pam_handle_t *pamh = NULL;
    int rc = pam_start_confdir(argv[2], argv[3], &c, argv[1], &pamh);
    if (rc != PAM_SUCCESS) {
        (void)fprintf(stderr, "pam_start_confdir: %s\n", pam_strerror(NULL, rc));
        return 1;
    }
    rc = pam_authenticate(pamh, 0);
    printf("result: %s (%d)\n", pam_strerror(pamh, rc), rc);
    (void)pam_end(pamh, rc);
    return rc == PAM_SUCCESS ? 0 : 1;
}

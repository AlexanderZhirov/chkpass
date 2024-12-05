module chkpass.user.auth;

import chkpass.libpam;

import std.string : toStringz;
import core.stdc.stdlib;
import std.conv;
import core.stdc.string : strdup, strstr;
import std.format;

import singlog;

enum {
    AUTH_SUCCESS = 0,
    AUTH_ERR_USER = 1,
    AUTH_ERR_PASS = 2,
    AUTH_ERR_NPASS = 3,
    AUTH_ERR_START = 4,
    AUTH_ERR_AUTH = 5,
    AUTH_ERR_ACCT = 6,
    AUTH_ERR_CHTOK = 7,
    AUTH_ERR_END = 8
}

private:

struct PAMdata {
    string password;
    string newPassword;
}

extern(C) int conversation_func(int num_msg, const PamMessage **msg, PamResponse **resp, void *appdata_ptr) {
    PAMdata *data = cast(PAMdata*)appdata_ptr;

    PamResponse *responses = cast(PamResponse *)calloc(num_msg, PamResponse.sizeof);

    if (responses == null) {
        return PAM_BUF_ERR;
    }

    for (int count = 0; count < num_msg; ++count) {
        responses[count].resp_retcode = 0;
        switch (msg[count].msg_style) {
            case PAM_PROMPT_ECHO_ON:
            case PAM_PROMPT_ECHO_OFF:
                switch (msg[count].msg.to!string) {
                    case "New password: ":
                    case "Retype new password: ":
                        responses[count].resp = strdup(data.newPassword.toStringz);
                        break;
                    case "Password: ":
                    case "Current password: ":
                        responses[count].resp = strdup(data.password.toStringz);
                        break;
                    default:
                        responses[count].resp = null;
                        break;
                }
                break;
            default:
                responses[count].resp = null;
                break;
        }
    }

    *resp = responses;
    
    return PAM_SUCCESS;
}

public:

class Auth {
    int authenticate(string pamod, string username, string password) {
        if (!username.length) {
            log.e("%s:%d: Username cannot be empty".format(__FUNCTION__, __LINE__));
            return AUTH_ERR_USER;
        }

        if (!password.length) {
            log.e("%s:%d: Password cannot be empty".format(__FUNCTION__, __LINE__));
            return AUTH_ERR_PASS;
        }

        PamConv *pamh = null;
        int retval = 0;

        PAMdata data = { password };
        void *appdata_ptr = &data;

        PamConv conv = { cast(conversation*)&conversation_func, appdata_ptr };

        retval = pam_start(pamod.toStringz, username.toStringz, &conv, &pamh);
        if (retval != PAM_SUCCESS) {
            log.e("%s:%d: %s".format(__FUNCTION__, __LINE__, pam_strerror(pamh, retval).to!string));
            return AUTH_ERR_START;
        }

        retval = pam_authenticate(pamh, 0);
        if (retval != PAM_SUCCESS) {
            log.e("%s:%d: %s".format(__FUNCTION__, __LINE__, pam_strerror(pamh, retval).to!string));
            pam_end(pamh, retval);
            return AUTH_ERR_AUTH;
        }

        retval = pam_end(pamh, PAM_SUCCESS);
        if (retval != PAM_SUCCESS) {
            log.e("%s:%d: %s".format(__FUNCTION__, __LINE__, pam_strerror(pamh, retval).to!string));
            return AUTH_ERR_END;
        }

        return AUTH_SUCCESS;
    }

    int changePassword(string pamod, string username, string password, string newPassword) {
        if (!username.length) {
            return AUTH_ERR_USER;
        }

        if (!password.length) {
            return AUTH_ERR_PASS;
        }

        if (!newPassword.length) {
            return AUTH_ERR_NPASS;
        }

        PamConv *pamh = null;
        int retval = 0;

        PAMdata data = { password, newPassword };
        void *appdata_ptr = &data;

        PamConv conv = { cast(conversation*)&conversation_func, appdata_ptr };

        retval = pam_start(pamod.toStringz, username.toStringz, &conv, &pamh);
        if (retval != PAM_SUCCESS) {
            log.e("%s:%d: %s".format(__FUNCTION__, __LINE__, pam_strerror(pamh, retval).to!string));
            return AUTH_ERR_START;
        }

        retval = pam_acct_mgmt(pamh, 0);
        if (retval != PAM_SUCCESS) {
            log.e("%s:%d: %s".format(__FUNCTION__, __LINE__, pam_strerror(pamh, retval).to!string));
            pam_end(pamh, retval);
            return AUTH_ERR_ACCT;
        }

        retval = pam_chauthtok(pamh, 0);
        if (retval != PAM_SUCCESS) {
            log.e("%s:%d: %s".format(__FUNCTION__, __LINE__, pam_strerror(pamh, retval).to!string));
            pam_end(pamh, retval);
            return AUTH_ERR_CHTOK;
        }

        retval = pam_end(pamh, PAM_SUCCESS);
        if (retval != PAM_SUCCESS) {
            log.e("%s:%d: %s".format(__FUNCTION__, __LINE__, pam_strerror(pamh, retval).to!string));
            return AUTH_ERR_END;
        }

        return AUTH_SUCCESS;
    }
}

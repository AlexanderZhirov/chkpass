module chkpass.libpam.types;

extern(C):

struct PamMessage {
    int msg_style;
    const(char) *msg;
}

struct PamResponse {
    char *resp;
    int	resp_retcode;
}

alias conversation = int function(int num_msg, const PamMessage **msg, PamResponse **resp, void *appdata_ptr);

struct PamConv {
    conversation *conv;
    void *appdata_ptr;
}

const (char) *pam_strerror(PamConv *pamh, int errnum);

enum PAM_SUCCESS = 0;
enum PAM_OPEN_ERR = 1;
enum PAM_SYMBOL_ERR = 2;
enum PAM_SERVICE_ERR = 3;
enum PAM_SYSTEM_ERR = 4;
enum PAM_BUF_ERR = 5;
enum PAM_PERM_DENIED = 6;
enum PAM_AUTH_ERR = 7;
enum PAM_CRED_INSUFFICIENT = 8;
enum PAM_AUTHINFO_UNAVAIL = 9;
enum PAM_USER_UNKNOWN = 10;
enum PAM_MAXTRIES = 11;
enum PAM_NEW_AUTHTOK_REQD = 12;
enum PAM_ACCT_EXPIRED = 13;
enum PAM_SESSION_ERR = 14;
enum PAM_CRED_UNAVAIL = 15;
enum PAM_CRED_EXPIRED = 16;
enum PAM_CRED_ERR = 17;
enum PAM_NO_MODULE_DATA = 18;
enum PAM_CONV_ERR = 19;
enum PAM_AUTHTOK_ERR = 20;
enum PAM_AUTHTOK_RECOVERY_ERR = 21;
enum PAM_AUTHTOK_LOCK_BUSY = 22;
enum PAM_AUTHTOK_DISABLE_AGING = 23;
enum PAM_TRY_AGAIN = 24;
enum PAM_IGNORE = 25;
enum PAM_ABORT = 26;
enum PAM_AUTHTOK_EXPIRED = 27;
enum PAM_MODULE_UNKNOWN = 28;
enum PAM_BAD_ITEM = 29;
enum PAM_CONV_AGAIN = 30;
enum PAM_INCOMPLETE = 31;
enum _PAM_RETURN_VALUES = 32;

enum PAM_PROMPT_ECHO_OFF = 1;
enum PAM_PROMPT_ECHO_ON = 2;
enum PAM_ERROR_MSG = 3;
enum PAM_TEXT_INFO = 4;

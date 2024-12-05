module chkpass.libpam.pam;

import chkpass.libpam.types;

extern(C):

int pam_start(const(char) *service_name, const(char) *user, const PamConv *pam_conversation, PamConv **pamh);
int pam_authenticate(PamConv *pamh, int flags);
int pam_end(PamConv *pamh, int pam_status);
int pam_chauthtok(PamConv *pamh, int flags);
int pam_acct_mgmt(PamConv *pamh, int flags);

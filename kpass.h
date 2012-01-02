#ifndef __KPASS_H__
#define __KPASS_H__

char *obtain_errormsg(void);

int kpass(char *username, char *password, char *service, char *host, char *kt_pathname);

#endif /* __KPASS_H__ */

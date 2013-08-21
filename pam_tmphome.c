#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <fcntl.h>
#include <libutil.h>
#include <paths.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <dirent.h>
#include <ftw.h>

#define PAM_SM_SESSION

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_mod_misc.h>


#define HOME_PATH "/temporary"
#define HOME_PATH_TEMPLATE "/temporary/home"

extern char **environ;

int processNode(const char *name, const struct stat *status, int type, struct FTW *ftw) {
	/* rmdir directories and unlink anything else */
	switch(type) {
		case FTW_DP:
			rmdir(name);
			break;
		default:
			unlink(name);
	}

	return 0;
}


/* copied from pam_mkhomedir */
void
copymkdir(char const * dir, char const * skel, mode_t mode, uid_t uid, gid_t gid)
{
	int             rc = 0;
	char            src[MAXPATHLEN];
	char            dst[MAXPATHLEN];

	if (mkdir(dir, mode) != 0 && errno != EEXIST) {
		PAM_LOG("mkdir(%s)", dir);
	} else {
		int             infd, outfd;
		struct stat     st;

		static char     counter = 0;
		static char    *copybuf = NULL;

		++counter;
		chown(dir, uid, gid);
		if (skel == NULL || *skel == '\0')
			rc = 1;
		else {
			DIR            *d = opendir(skel);

			if (d != NULL) {
				struct dirent  *e;

				while ((e = readdir(d)) != NULL) {
					char           *p = e->d_name;

					if (snprintf(src, sizeof(src), "%s/%s", skel, p) >= (int)sizeof(src))
						PAM_LOG("warning: pathname too long '%s/%s' (skel not copied)", skel, p);
					else if (stat(src, &st) == 0) {
						if (strncmp(p, "dot.", 4) == 0) /* Conversion */
							p += 3;
						if (snprintf(dst, sizeof(dst), "%s/%s", dir, p) >= (int)sizeof(dst))
							PAM_LOG("warning: path too long '%s/%s' (skel file skipped)", dir, p);
						else {
							if (S_ISDIR(st.st_mode)) {  /* Recurse for this */
								if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0)
									copymkdir(dst, src, (st.st_mode & 0777), uid, gid);
								chflags(dst, st.st_flags);      /* propogate flags */
								/*
								 * Note: don't propogate special attributes
								 * but do propogate file flags
								*/
							} else if (S_ISREG(st.st_mode) && (outfd = open(dst, O_RDWR | O_CREAT | O_EXCL, st.st_mode)) != -1) {
								if ((infd = open(src, O_RDONLY)) == -1) {
									close(outfd);
									remove(dst);
								} else {
									int b;

									/*
									 * Allocate our copy buffer if we need to
  									 */
									if (copybuf == NULL)
										copybuf = malloc(4096);
									while ((b = read(infd, copybuf, 4096)) > 0)
										write(outfd, copybuf, b);
									close(infd);
									/*
									 * Propogate special filesystem flags
									 */
									fchown(outfd, uid, gid);
									fchflags(outfd, st.st_flags);
									close(outfd);
									chown(dst, uid, gid);
								}
							}
						}
					}
				}
 				closedir(d);
			}
		}
		if (--counter == 0 && copybuf != NULL) {
			free(copybuf);
			copybuf = NULL;
		}
	}
}
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags __unused, int argc , const char *argv[] ) {
	int i=0, pam_err = 0;
	struct passwd *pwd;
	const char *user = NULL;
	char *tmp_home = NULL;
	mode_t *set = NULL;
	char modeval[5];
	
	/* Default values */
	strncpy(modeval,"0755",sizeof(modeval));
 
	/* Get the user entry for the logged in user */
	if ((pam_err = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS)
		return (pam_err);
	if (user == NULL || (pwd = getpwnam(user)) == NULL)
		return (PAM_SERVICE_ERR);
	
	/* Home should be set to /temporary */
	if(strncmp(pwd->pw_dir, HOME_PATH, strlen(HOME_PATH))) {
		PAM_LOG("Ignoring standard user\n");
		return (PAM_SERVICE_ERR);
	}
	
	/* We need a writable string for mkdtemp */
	asprintf(&tmp_home, "%s.XXXXXX", HOME_PATH_TEMPLATE);
	

	/* Now create the temporary home directory */
	if(mkdtemp(tmp_home) == NULL) {
		PAM_LOG("Unable to create temporary home directory\n");
		return (PAM_SERVICE_ERR);
	}
	
	
	/* Get the chmod mode */
	if (( set=setmode(modeval) ) == NULL ) {
		PAM_LOG("Value set in mode is not a mode - see chmod(1) for details");
		return (PAM_SERVICE_ERR);
	}

	/* Copy the home directory over and change the permissions (copied from pam_mkhomedir */
	copymkdir(tmp_home, "/usr/share/skel", getmode(set, S_IRWXU | S_IRWXG | S_IRWXO), pwd->pw_uid,pwd->pw_gid);

	/* Set the HOME environment variable */
	pam_setenv(pamh, "HOME", tmp_home, 1);

	/* Clean up and return */
	free(tmp_home);

	return PAM_SUCCESS;	
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh,
	int flags __unused, int argc, const char *argv[] ) {
	
	char *tmp_home = NULL;
	
	/* Retrieve the users home */
	if((tmp_home = pam_getenv(pamh, "HOME")) == NULL) {
		PAM_LOG("Unable to retrieve home from the user's environment\n");
		return PAM_SERVICE_ERR;
	}

	/* Make sure it's one of our temp directories */
	if(strncmp(tmp_home, HOME_PATH_TEMPLATE, strlen(HOME_PATH_TEMPLATE))) {
		PAM_LOG("%s is not one of our temporary directories\n");
		return PAM_SERVICE_ERR;
	}

	/* We should now be good to remove the directory */	
	nftw(tmp_home, processNode, 1, FTW_PHYS | FTW_DEPTH | FTW_MOUNT);
	return PAM_SUCCESS;
}

PAM_MODULE_ENTRY("pam_tmphome");

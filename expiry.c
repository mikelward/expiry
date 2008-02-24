/**
 * $Id: expiry.c,v 1.2 2005/09/28 04:27:20 mwardle Exp $
 * Show password expiration information for the named user.
 */

#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <shadow.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/**
 * Exit status codes
 */
#undef EX_SUCCESS
#define EX_SUCCESS 0
#undef EX_FAILURE
#define EX_FAILURE 1
#undef EX_USAGE
#define EX_USAGE 2
#undef EX_EXPIRED
#define EX_EXPIRED 3
#undef EX_VALID
#define EX_VALID 0

/**
 * Program constants
 */
#undef SECS_IN_DAY
#define SECS_IN_DAY (60 * 60 * 24)
#undef DATEBUF_MAX
#define DATEBUF_MAX 256

const char *cvsid = "$Id: expiry.c,v 1.2 2005/09/28 04:27:20 mwardle Exp $";
const char *progname = "expiry";

int verbose = 0;	/* Whether to print extra information */

/**
 * Print a message describing how to run this program.
 */
void usage()
{
    fprintf(stderr, "%s: expiry <username>\n", progname);
}

int main(int argc, char **argv)
{
    char *username;
    struct passwd *ppasswd;
    struct spwd *pshadow;

    /**
     * Process the command line arguments.
     */
    if (argc >= 2)
    {
        int c;
        while ((c = getopt(argc, argv, "v")) != -1)
        {
            switch (c)
            {
                case 'v':
                    verbose = 1;
                    break;

                default:
                    usage();
                    exit(EX_USAGE);
            }
        }
        argc -= optind;
        argv += optind;

        username = argv[0];
    }
    else
    {
        fprintf(stderr, "No username supplied\n");
        exit(EX_USAGE);
    }

    /**
     * Get the user's password entry.
     */
    errno = 0;
    ppasswd = getpwnam(username);
    if (ppasswd)
    {
        if (verbose)
        {
            printf("User name:\t%s\n", ppasswd->pw_gecos);
        }
    }
    else
    {
        if (errno == 0)
        {
            fprintf(stderr, "User %s does not exist\n", username);
        }
        else
        {
            fprintf(stderr, "Cannot get password information for %s: %s\n",
                    username, strerror(errno));
        }
        exit(EX_FAILURE);
    }

    /**
     * Get the user's shadow password entry.
     */
    errno = 0;
    pshadow = getspnam(username);
    if (pshadow)
    {
        time_t last, now, age, expires, left;
        struct tm *plasttm = NULL;
        char *plaststr = NULL;

        /**
         * Determine the various times related to the password expiration,
         * converting between days and seconds where necessary.
         */
        now = time(NULL);
        last = pshadow->sp_lstchg * SECS_IN_DAY;
        age = now - last;
        expires = last + (pshadow->sp_max * SECS_IN_DAY);
        left = expires - now;

        /**
         * Get the time of the last password change as a human-readable date.
         */
        plasttm = localtime(&last);
        if (plasttm)
        {
            plaststr = malloc(DATEBUF_MAX);
            if (plaststr)
            {
                int ret;
                if (!strftime(plaststr, DATEBUF_MAX, "%e %b %Y", plasttm))
                {
                    plaststr = NULL;
                }
            }
        }

        if (plasttm && plaststr)
        {
            printf("Last password change:\t%s\n", plaststr);
        }
        else
        {
            printf("Last password change:\t%ld\n", pshadow->sp_lstchg);
        }

        /**
         * Print extra information about the password expiration if the user
         * enabled verbose mode.
         */
        if (verbose)
        {
            printf("Maximum password age:\t%ld days\n", pshadow->sp_max);
            printf("Current password age:\t%ld days\n", age / SECS_IN_DAY);
        }

        /**
         * Print a message stating whether the password is valid or expired
         * and exit with the appropriate status code.
         */
        if (left > 0)
        {
            printf("Password expires in:\t%ld days\n", left / SECS_IN_DAY);
            exit(EX_VALID);
        }
        else
        {
            printf("Password expired:\t%ld days ago\n", left * -1 / SECS_IN_DAY);
            exit(EX_EXPIRED);
        }
    }
    else
    {
        fprintf(stderr, "Cannot get shadow password information for %s: %s\n",
                username, strerror(errno));
        exit(EX_FAILURE);
    }

    exit(EX_SUCCESS);
}

/* vi: set sw=4 ts=33: */

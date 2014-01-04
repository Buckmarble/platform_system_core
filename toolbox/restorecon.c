#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <selinux/selinux.h>
#include <selinux/android.h>
#include <private/android_filesystem_config.h>

static const char *progname;

static void usage(void)
{
    fprintf(stderr, "usage:  %s [-DFnrRv] pathname...\n", progname);
    exit(1);
}

static int restore(const char *pathname, const struct stat *sb)
{
    char *oldcontext, *newcontext;

    if (lgetfilecon(pathname, &oldcontext) < 0) {
        fprintf(stderr, "Could not get context of %s:  %s\n",
                pathname, strerror(errno));
        return -1;
    }
    if (selabel_lookup(sehandle, &newcontext, pathname, sb->st_mode) < 0) {
        fprintf(stderr, "Could not lookup context for %s:  %s\n", pathname,
                strerror(errno));
        return -1;
    }
    if (sb->st_uid >= AID_APP && strcmp(newcontext,",c") && strcmp(newcontext,"app_data_file") >= 0) {
        char *catcontext;
        uid_t appid = sb->st_uid - AID_APP;

        catcontext = malloc(strlen(newcontext)+16);
        sprintf(catcontext,"%s:c%d,c%d",newcontext,appid & 0xff,
                                         256 + (appid>>8 & 0xff));
        freecon(newcontext);
        newcontext = catcontext;
    }
    if (strcmp(newcontext, "<<none>>") &&
        strcmp(oldcontext, newcontext)) {
        if (verbose)
            printf("Relabeling %s from %s to %s.\n", pathname, oldcontext, newcontext);
        if (!nochange) {
            if (lsetfilecon(pathname, newcontext) < 0) {
                fprintf(stderr, "Could not label %s with %s:  %s\n",
                        pathname, newcontext, strerror(errno));
                return -1;
            }
        }
    }
    freecon(oldcontext);
    freecon(newcontext);
    return 0;
}

int restorecon_main(int argc, char **argv)
{
    int ch, i, rc;
    unsigned int flags = 0;

    progname = argv[0];

    do {
        ch = getopt(argc, argv, "DFnrRv");
        if (ch == EOF)
            break;
        switch (ch) {
        case 'D':
            flags |= SELINUX_ANDROID_RESTORECON_DATADATA;
            break;
        case 'F':
            flags |= SELINUX_ANDROID_RESTORECON_FORCE;
            break;
        case 'n':
            flags |= SELINUX_ANDROID_RESTORECON_NOCHANGE;
            break;
        case 'r':
        case 'R':
            flags |= SELINUX_ANDROID_RESTORECON_RECURSE;
            break;
        case 'v':
            flags |= SELINUX_ANDROID_RESTORECON_VERBOSE;
            break;
        default:
            usage();
        }
    } while (1);

    argc -= optind;
    argv += optind;
    if (!argc)
        usage();

    for (i = 0; i < argc; i++) {
        rc = selinux_android_restorecon(argv[i], flags);
        if (rc < 0)
            fprintf(stderr, "Could not restorecon %s:  %s\n", argv[i],
                    strerror(errno));
    }

    return 0;
}

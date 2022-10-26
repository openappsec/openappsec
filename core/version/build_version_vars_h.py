import os
import getpass
import datetime
import time
import subprocess
import sys

# collect build data

now = datetime.datetime.now()
build_id = "0.0"
is_public = "true"
username = "%s" % getpass.getuser()
timestamp = "%s%s" % (now.replace(microsecond=0).isoformat(), time.strftime("%z"))
version_prefix = "1."
full_version = "%s%s" % (version_prefix, build_id)

branch = os.getenv("CI_BUILD_REF_NAME")
if branch is None:
    branch = "private"

# Generate a h file with static varaibles to return the version:
h_code = '''
#ifndef __VERSION_VARS_H__
#define __VERSION_VARS_H__

static const bool is_public = %s;
static const char *id = "%s";
static const char *user = "%s";
static const char *timestamp = "%s";
static const char *version_prefix = "%s";
static const char *version_branch = "%s";

#endif // __VERSION_VARS_H__

'''

kernel_h_code = '''
#ifndef __KERNEL_VERSION_VARS_H__
#define __KERNEL_VERSION_VARS_H__

#define AGENT_FULL_VERSION  "%s"

#endif // __KERNEL_VERSION_VARS_H__

'''
if sys.argv[1] == 'print-version-only':
    print(full_version)
elif sys.argv[1] == 'kernel':
    print(kernel_h_code % (full_version))
else:
    print(h_code % (is_public, build_id, username, timestamp, version_prefix, branch))

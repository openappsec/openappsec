#!/bin/sh

FILESYSTEM_PATH="/etc/cp"
. "/etc/environment"
if [ -n "${CP_ENV_FILESYSTEM}" ] ; then
    FILESYSTEM_PATH=$CP_ENV_FILESYSTEM
fi

AC_MODULES_MONITOR_NAME=cp-nano-access-control-kernel-modules-monitor.sh
WD_SERVICES=${FILESYSTEM_PATH}/watchdog/wd.services

if [ -z "$(grep $AC_MODULES_MONITOR_NAME $WD_SERVICES)" ]; then
    exit 0
fi

sleep 60 && kill "$$" &
while [ -z "$(lsmod | grep cp_nano)"  ]; do
    continue
done
exit 0

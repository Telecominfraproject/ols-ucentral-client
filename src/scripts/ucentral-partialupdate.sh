#!/bin/bash

pipe="/var/lib/ucentral/upgrade_pipe"
logs_f="/var/lib/ucentral/logs"

function upgrade()
{
  local file="$1"

  if file $file | grep "Debian binary package" >/dev/null 2>&1 ; then
    echo "Trying to install '$file' deb..."
    # Give ucentral app at least some time to flush logs / upgrade state etc
    # The problem is there's no other way to secure upgrade state report
    # to GW, since this pipe is 'one-way-only' mechanism (to simplify implementation).
    # Without this sleep, ucentral app might not even be able to report upgrade state,
    # as internally it uses polling mechanism (every 1 sec), and running this script
    # kills ucentral-docker immediately.
    # More elegant solution / WA TBD.
    #
    # TBD: verify integrity of package itself, report fails back to the app
    # to prevent situations where client's been removed, but the package itself
    # is broken and thus connection to GW's been lost.
    sleep 5
      sudo dpkg -r ucentral-client &&
      sudo dpkg -i $file &&
      rm -f $file &&
      sudo reboot && exit 0
  else
    echo "Invalid '$file' file received for partial (deb) upgrade!"
  fi

}

function handle_pipe_cmd()
{
  case $1 in
    exit)
      echo "exit cmd received...now exiting"
      exit
    ;;
    upgrade)
      echo "'upgrade' '$2' (argument) cmd received...now starting upgrade procedure"
      upgrade $2
    ;;
    *)
      echo "unknown cmd received '$1'"
    ;;
  esac
}

function entry() {
  echo "Running as daemon"
  while true; do
    cmd="$(cat /var/lib/ucentral/upgrade_pipe)";
    handle_pipe_cmd $cmd
  done
}

mkfifo $pipe 2>/dev/null || true
chmod 666 $pipe
entry </dev/null >$logs_f 2>&1

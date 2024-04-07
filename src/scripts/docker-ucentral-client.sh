#!/bin/bash

DEBUGLOG="/tmp/ucentral-client_debug.log"

function debug()
{
    /usr/bin/logger $1
    /bin/echo `date` "- $1" >> ${DEBUGLOG}
}


function getBootType()
{
    # same code snippet in files/scripts/syncd.sh
    case "$(cat /proc/cmdline)" in
    *SONIC_BOOT_TYPE=warm*)
        TYPE='warm'
        ;;
    *SONIC_BOOT_TYPE=fastfast*)
        TYPE='fastfast'
        ;;
    *SONIC_BOOT_TYPE=fast*|*fast-reboot*)
        TYPE='fast'
        ;;
    *)
        TYPE='cold'
    esac
    echo "${TYPE}"
}

function preStartAction()
{
    : # nothing
}

function postStartAction()
{
    : # nothing
}

start() {

    # Obtain boot type from kernel arguments
    BOOT_TYPE=`getBootType`

    DOCKERCHECK=`docker inspect --type container ${DOCKERNAME} 2>/dev/null`
    if [ "$?" -ne "0" ]; then

		DOCKER_LIMITS=$(
			cat <<-EOF
			{
				"cpus" : "auto",
				"cpu-shares" : "1024",
				"cpuset" : "notused",
				"memsize" : "auto"
			}
			EOF
			)

		cat <<<$(jq '.ucentral_client='"${DOCKER_LIMITS}"'' /etc/sonic/docker_limits.json || cat /etc/sonic/docker_limits.json) >/etc/sonic/docker_limits.json

		echo "Creating new ${DOCKERNAME} container with HWSKU $HWSKU"
		NET="host"
		docker create  \
			$(sonic-dockerlimits -sys ucentral_client) \
			--net=$NET \
			-e RUNTIME_OWNER=local \
			-e UC_GATEWAY_ADDRESS=gw.dev01.apps.shastacloud.com \
			--uts=host \
			-v /etc/localtime:/etc/localtime:ro \
			--tmpfs /tmp \
			-v /sys/kernel/debug:/sys/kernel/debug \
			--tmpfs /var/tmp \
			--mount type=bind,src=/dev/log,dst=/dev/log \
			-v TCA:/etc/ucentral:ro \
			-v /tmp/gnma:/etc/gnma \
			-v /var/lib/ucentral:/var/lib/ucentral \
			-v /var/dump:/var/dump \
			--tty \
			--name=$DOCKERNAME ucentral-client:latest || {
				echo "Failed to docker run" >&1
				exit 4
			}
			sonic-dockerlimits -updatedef ucentral_client
			if [ $? -eq 0 ]; then
				echo "Applied the original memlimits on docker ucentral-client"
			fi
    fi
    preStartAction
    # TEMP workaround: do not wait for SWSS, start container anyway
    # (NOTE: currently, doesn't depend on the SWSS, so no harm)
    #/usr/local/bin/container start ${DOCKERNAME}
    docker container start ${DOCKERNAME}
    postStartAction
}

wait() {

    /usr/local/bin/container pre-wait $DOCKERNAME
    docker_pid="$(docker inspect -f {{.State.Pid}} $DOCKERNAME)"
    tail --pid=$docker_pid -f /dev/null
}

stop() {
    DOCKERCHECK=`docker inspect --type container ${DOCKERNAME} &>/dev/null`
    if [ $? -eq 0 ]; then
        /usr/local/bin/container stop $DOCKERNAME
        if [ $? -ne 0 ]; then
            echo "Failed to stop $DOCKERNAME"
        fi
    fi
}

remove() {
    # Remove the docker container image and disable the container service
    DOCKERCHECK=`docker inspect --type container ${DOCKERNAME} &>/dev/null`
    if [ $? -eq 0 ]; then
        docker rm -f ${DOCKERNAME}
    fi
    docker images -a | grep "ucentral-client" | awk '{print $3}' | xargs docker rmi
}





DOCKERNAME=ucentral_client
OP=$1
DEV=$2 # namespace/device number to operate on
NAMESPACE_PREFIX="asic"
DOCKERNAME=$DOCKERNAME$DEV
if [ "$DEV" ]; then
    NET_NS="$NAMESPACE_PREFIX$DEV" #name of the network namespace

 else
    NET_NS=""
fi

# read SONiC immutable variables
[ -f /etc/sonic/sonic-environment ] && . /etc/sonic/sonic-environment

case "$1" in
    start|wait|stop|remove)
        $1
        ;;
    *)
        echo "Usage: $0 {start namespace(optional)|wait namespace(optional)|stop namespace(optional)}"
        exit 1
        ;;
esac

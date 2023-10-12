#!/bin/bash

echo "uCentral Client"

start() {
    UCENTRAL_CLIENT=/usr/local/lib/docker-ucentral-client.gz
    if [[ -e ${UCENTRAL_CLIENT} ]]; then
        if docker load < ${UCENTRAL_CLIENT} ;then
            rm ${UCENTRAL_CLIENT}
        fi
    fi

    cp /usr/local/lib/OLS_NOS_fixups.script /home/admin/OLS_NOS_fixups.script
    cp /usr/local/lib/OLS_NOS_upgrade_override.script /home/admin/OLS_NOS_upgrade_override.script

    if [ $(systemctl is-active config-setup.service) == "active" ]; then
        # do nothing on service restart
        return
    fi

    # Disable SONiC native ZTP
    systemctl disable ztp
    test -d /host/ztp >/dev/null 2>&1 || mkdir /host/ztp >/dev/null 2>&1
    echo '{ "admin-mode" : false}' > /host/ztp/ztp_cfg.json
    # Remove ZTP DHCP policy which is used by interfaces-config.sh
    rm -f /etc/network/ifupdown2/policy.d/ztp_dhcp.json

    # TODO: Check whether DHCP client hooks are required.
    #       E.g., similar to /etc/dhcp/dhclient-enter-hooks.d/inband-ztp-ip
}

wait() {
    test -d /var/lib/ucentral || mkdir /var/lib/ucentral

    # Wait for at least one Vlan to be created - a signal that telemetry is up.
    # Even if vlan table is empty, private 3967 will be allocated with all
    # ports in it.
    while ! ls /sys/class/net/Vlan* &>/dev/null; do sleep 1; done

    # Detect first boot on this version
    # Run upgrade overrides before fixups
    conf_upgrade_md5sum=$(md5sum /home/admin/OLS_NOS_upgrade_override.script | cut -d ' ' -f1)
    if test "$conf_upgrade_md5sum" != "$(test -f /var/lib/ucentral/upgrade-override.md5sum && cat /var/lib/ucentral/upgrade-override.md5sum)"; then
	    sudo -u admin -- bash "sonic-cli" "/home/admin/OLS_NOS_upgrade_override.script"
	    echo -n "$conf_upgrade_md5sum" >/var/lib/ucentral/upgrade-override.md5sum
    fi

    # Temporary NTP fixup / WA: configure a list of default NTP servers.
    # Should mature into a default-config option to make sure board has right
    # time upon any boot (especially first time).
    sudo -u admin -- bash "sonic-cli" "/home/admin/OLS_NOS_fixups.script"

    # Mount the uCentral volume for client CA certificate
    # TODO

    # Fix networking behaviour for management vlan:
    # As Vlan1 is not exist on boot time + could has lack of support hotplug -
    # we need to explicity ifup it to notify networking.
    # NOTE: alternatively we could use ifplugd. This also handle del/add scenario
    ifup Vlan1 || true

    # There's an issue with containers starting before DNS server is configured:
    # resolf.conf file get copied from host to container upon container start.
    # This means, that if resolf.conf gets altered (on host) after container's been
    # started, these changes are not reflected in any way on the container itself
    # (most like it's empty).
    # This causes any DNS resolves (clientauth for example) to fail, inherently
    # making ucentral app useless up untill reboot / container restart.
    #
    # A W/A is the following:
    #
    # Wait for dhcp lease / network to be up - a URI we use for redirector
    # should be accessible.
    # This also means, that we won't start up untill this URI is accessible.
    while ! curl clientauth.one.digicert.com &>/dev/null; do sleep 1; done

    # change admin password
    # NOTE: This could lead to access escalation, if you got image from running device
    if ! test -f /var/lib/ucentral/admin-cred.changed; then
	    #ADMIN_PASSWD=`openssl rand -hex 10`
	    ADMIN_PASSWD=broadcom
	    # Save password
	    echo -n $ADMIN_PASSWD >/var/lib/ucentral/admin-cred.buf
	    sudo -u admin sonic-cli -c "configure" -c "username admin password $ADMIN_PASSWD role admin"
	    touch /var/lib/ucentral/admin-cred.changed
    fi

    #generate private account
    GNMI_PASSWD=`openssl rand -hex 10`
    sudo -u admin sonic-cli -c "configure" -c "username ucentral_gnmi_private password $GNMI_PASSWD role admin"

    docker volume inspect TCA >/dev/null 2>&1 && docker volume rm TCA >/dev/null 2>&1

    docker volume create --driver local --opt type=ext4 --opt device=/dev/disk/by-label/ONIE-TIP-CA-CERT TCA
    rm -r /tmp/gnma >/dev/null 2>&1 || true
    mkdir /tmp/gnma
    echo '{"auth_login": "ucentral_gnmi_private", "auth_passwd": "'$GNMI_PASSWD'"}' >/tmp/gnma/gnma.conf

    # start the ucentral partial upgrade script
    # NOTE: we need systemd to run it as a separate procgroup process,
    # since upon deb reinstall systemd will definetely try to kill this process,
    # hence making deb reinstall impossible.
    systemd-run -P /usr/local/bin/ucentral-partialupdate.sh </dev/null & disown

    # start the ucentral container
    bash /usr/local/bin/docker-ucentral-client.sh start
    bash /usr/local/bin/docker-ucentral-client.sh wait
}

stop() {
    # stop the ucentral container
    bash /usr/local/bin/docker-ucentral-client.sh stop
}

remove() {
    bash /usr/local/bin/docker-ucentral-client.sh remove
}

case "$1" in
    start|wait|stop|remove)
        $1
        ;;
    *)
        echo "Usage: $0 {start namespace(optional)|wait namespace(optional)|stop namespace(optional)}"
        exit 1
        ;;
esac

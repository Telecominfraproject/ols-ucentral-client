#!/bin/sh

REQUIRED_CERT_FILES="cas.pem cert.pem key.pem dev-id"

function partition_replace_certs()
{
    local certs_rootdir=${2}

    tmp_dir=`mktemp -d`
    mount /dev/$1 ${tmp_dir} 2>&1 >/dev/null
    if [ $? -ne 0 ] ; then
        echo "Failed to create/mount partition"
        exit 2
    fi

    rm -rf ${tmp_dir}/lost\+found 2>&1 >/dev/null

    for x in $REQUIRED_CERT_FILES ; do
        echo "Copying cert file ${certs_rootdir}/$x to partition..."
        cp ${certs_rootdir}/$x ${tmp_dir}
        if [ $? -ne 0 ] ; then
            echo "Failed to copy ${certs_rootdir}/$x to partition..."
            umount /dev/$1
            exit 3
        fi
    done

    echo "MD5SUM after replace:"
    md5sum ${tmp_dir}/*
    sync;

    echo && echo "### Certificates has been copied successfully!" && echo
    sync &&
    umount ${tmp_dir} 2>&1 >/dev/null
    rm -rf ${tmp_dir} 2>&1 >/dev/null
}

function get_first_free_partition()
{
    for x in $(seq 1 10) ; do (ls /dev/${dev_name}${x} 2>&1 >/dev/null) || break; done 
    return ${x}
}

function partition_create()
{
    get_first_free_partition 2>&1 >/dev/null
    local part_idx=$?
    local dev_name=${1}
    local part_offs_start=${2}
    local part_offs_end=${3}
    local part_guid=${4}
    local part_name=${5}
    local tmp_dir=

    echo "Trying to create part idx ${part_idx}"

    sgdisk -n ${part_idx}:${part_offs_start}:${part_offs_end} \
           -t ${part_idx}:${part_guid} \
           -c ${part_idx}:${part_name} \
           /dev/${dev_name} 2>&1 >/dev/null && echo "Created partition" && \
    partprobe &&
    sync &&
    mkfs.ext4 -F -L ${part_name} /dev/${dev_name}${part_idx} &&
    partprobe &&
    parted -l | grep ${part_name} && echo &&
    tune2fs -l /dev/${dev_name}${part_idx} | grep ${part_name} &&
    echo && echo "### Partition ${part_name} has been created at /dev/${dev_name}${part_idx}" && echo
    if [ $? -ne 0 ] ; then
        echo "Partition create failed..."
        exit 1
    fi
    partition_replace_certs "${dev_name}${part_idx}" "${6}"
}

function check_cert_file_exists()
{
    if [ ! -e "$1" ] ; then
        echo "File <$1> does not exists, or provided root directory is invalid"
        exit 1
    fi
}

if [ ! -d "$1" ] ; then
    echo "Root directory <$1> does not exists, or it's not a directory."
    echo "Please specify a valid folder that holds device certificates to be installed."
    exit 1
fi

for x in $REQUIRED_CERT_FILES ; do
    echo "Checking if $1/$x exists..."
    check_cert_file_exists "$1/$x"
done;

dmidecode | grep -i 'manufacturer' | grep QEMU 2>&1 >/dev/null
if [ $? -eq 0 ] ; then
    dev_name="vda"
else
    dev_name="sda"
fi

echo "Parted list before changes:"
parted -l
# Following are valid for as4630_54pe-r0
# Device name: base device "name" - vda for Virtual, sda for physical devices
# Part num: <dynamic>, starting sector: 34, end sector: 2047
# Partition type - 8300 Linux filesystem
# Label - 'ONIE-TIP-CA-CERT'
sgdisk -p /dev/${dev_name} | grep TIP-CA-CERT 2>&1 >/dev/null
if [ $? -ne 0 ] ; then
    echo "No <ONIE-TIP-CA-CERT> part found, creating..."
    partition_create $dev_name 34 2047 8300 "ONIE-TIP-CA-CERT" $1
    if [ $? -ne 0 ] ; then
        echo "Partition create failed"
        exit 1
    fi
else
    echo "Partition 'ONIE-TIP-CA-CERT' already exists... not creating"
    echo "Trying to replace certificate on existing partition with new ones..."
    cert_part_idx=`sgdisk -p /dev/${dev_name} | grep TIP-CA-CERT | tail -1 | awk -F'[^0-9]+' '{ print $2 }' 2>/dev/null`
    echo "Cert partition is ${dev_name}${cert_part_idx}"
    partition_replace_certs "${dev_name}${cert_part_idx}" $1
fi
echo
echo "### Parted list after changes:"
parted -l
exit 0

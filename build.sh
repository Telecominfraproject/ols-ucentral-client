#!/bin/bash

DIR=$(dirname `readlink -f $0`)

usage()
{
cat << EOF
Usage: sh build.sh <amd64(default)|arm64|-h>
  example: 
        sh build.sh arm64
        sh build.sh
EOF
}

build()
{
    cur_dir=$(pwd)
    cd $DIR
    GOARCH=$1 CGO_ENABLED=0 go build cmd/*.go
    rc=$?
    cd $cur_dir
    return $rc
}

main()
{
    arch=
    case $1 in
        ''|amd64)
            arch=amd64
            ;;
        arm64)
            arch=arm64
            ;;
        *)
            echo "error: invalid arch: $1 "
            usage
            return 1
            ;;
    esac

    build $arch
}

case $1 in
    -h|--help|help)
        usage
        exit 0
        ;;
    *)
        main $@
        exit $?
        ;;
esac

exit $?
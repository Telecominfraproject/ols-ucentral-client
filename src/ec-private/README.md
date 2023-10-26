# Ucentral for EC

Ucentral solution for EC is made of the following parts:
* `ecapi`: a library to communicate with EC via SNMP

# Compiling

## EC Build for Target Device

First build the full EC image for your target device:
* `cd EC_VOB/project_build_environment/<target device>`
* `./make_all`

If this is successful, you can proceed to the next step.

## Build Environment

To successfully build required components the build environments variables must be prepared:
* `cd EC_VOB/project_build_environment/<target device>`
* `cd utils`
* `. build_env_init`

## Building All Components

Presumably you have checked out the [ols-ucentral-src]:
* `cd [ols-ucentral-src]`
* Run `make plat-ec`, which should successfully compile all components

## Creating EC Firmware with Ucentral

After building everything up:
* Check the `output` directory, it should contain all required binaries in appropriate subdirectories
* Copy over these directories to your `EC_VOB/project_build_environment/<target device>/user/thirdpty/ucentral`

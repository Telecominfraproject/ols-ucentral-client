# What is it?
This repo holds the source code for OLS (OpenLAN Switching) uCentral client implementation.
It implements both the ZTP Gateway discovery procedure (calling the ZTP Redirector and locating
the desired Gateway to connect to), as well as handlers to process the Gateway requests.  
Upon connecting to the Gateway service, the device can be provisioned and controlled from the
cloud in the same manner as uCentral OpenWifi APs do.  

# Build System
The build system implements an automated dockerized-based build enviroment to produce a final
deb package that can be installed on the target Sonic NOS.  

The deb file includes the uCentral Client docker image, that runs uCentral application.  The
uCentral application establishes a secure connection with a uCentral-schema compatible Gateway
cloud service. The GW service can then provision the device via this secure channel, and the
uCentral application applies the configuration to the underlying device.

## Build intermediate steps include:
- Generation (and tagging) of docker image that acts as a dockerized build
  enviroment (library dependencies and the uCentral app are built inside
  this build-env img);
- Compilation of the uCentral app (and libraries) inside the dockerized build
  enviroment img;
- Generation of ucentral-client docker image (consists of libraries that the
  application depends on and the uCentral app itself);
- Generation of the final deb pkg that can be installed to the target Sonic NOS
  based device (consists of the ucentral-client docker image and service scripts
  etc);

# How to use the build system (all-in-once step):
1. Build <all> target (takes a while):
```
make all
```
2. Copy final deb pkg from output/ folder (ucentral-client_1.0_amd64.deb) to the
   target device;
```
file output/*deb
  output/ucentral-client_1.0_amd64.deb: Debian binary package (format 2.0)
scp output/*deb <remote_device>
```
3. Install deb on the target device (requires root priv; must run on the target
   device):
```
cd <folder where .deb was copied to>;  
dpkg -i ./ucentral-client_1.0_amd64.deb  
```
4. uCentral service should be up and runnig (automatically initiates GW discovery,
  GW connect; connection should be established and device should be present
  in the device list on the <gw-ui> webpage;  

 **_NOTE:_** TIP certs are not part of either final build img nor the build system
       itself; these should be mounted / installed manually, or be present upon
       service start;
       Detailed GUIDE on how-to create cert partition / install certs can be found under
       <Certificates> topic below.

## Makefile targets
**all**:  
Build whole project (build-host-env, ucentral-app, ucentral-docker-img, final deb)  

**build-host-env**:  
Build *ONLY* build-host-enviroment (docker image): install toolchain, host utils,
clone / build library dependencies (e.g. cJSON, libwebsockets etc).  

Later on, this docker image used to create a docker container that compiles
the uCentral application itself.  

Depends on the root Dockerfile: img is tagged with stripped SHA of Dockerfile
to prevent redundant rebuilds of host-env img;  

Also exports img to an archive file that can be also shared / installed on another PC.  
It can be found under the following folder:  
output/docker-ucentral-client-build-env-${IMG_TAG}.gz  

**run-host-env**:  
Start host-build-enviroment docker container (a simple helper target for active development)  

**run-ucentral-docker-img**:  
Run created uCentral docker image (and uCentral application) locally.
For development / debug purposes only.  

**build-ucentral-app**:  
Build (using host-build-enviroment docker img) the uCentral application (with
all the lib dependencies).  
Copy compiled binary (and library-dependencies) to the src/docker folder.  

**build-ucentral-docker-img**:  
Build docker image, that holds the uCentral application (also libs deps).  
Docker image (ucentral-client) is also created locally, so it can be launched
on host system as well.  

**build-final-deb**:  
Technically same as 'all'. Produces final .deb pkg that can be copied to target
and installed as native deb pkg.  

# Certificates
TIP Certificates should be preinstalled upon launch of the service. uCentral
client uses certificates to establish a secure connection with both Redirector
(firstcontact), as well as te GW itself.  

In order to create a partition, partition_script.sh (part of this repo)
can be used to do so, the steps are as follows (should be executed on device):
Enter superuser mode
```
$ sudo su
```
Create temp directory to copy certificates + script into, and unpack
Copy both certificates and partition script to the device:
```
$ mkdir /tmp/temp
$ cd /tmp/temp/
$ scp <remote_host>:/certificates/<some_mac>.tar ./
$ scp <remote_host>:/partition_script.sh ./
$ tar -xvf ./<some_mac>.tar
```
After certificate files are being unpacked, launch this script with single argument being
the path to the certificates directory (please note that BASH interpreter should be used explicitly,
it's done to make this script compatible with most ONIE builds as well, as they mostly
pack busybox / sh):
```
bash ./partition_script.sh ./
```
  
Once certificates are installed and partition is created, rebooting the device is required.
After reboot and uCentral start, service creates <TCA> volume upon start based on physical partition
(by-label provided by udev - /dev/disk/by-label/ONIE-TIP-CA-CERT) automatically.

# Testing

The repository includes a comprehensive testing framework for configuration validation:

## Running Tests

**Quick Start:**
```bash
# Using the test runner script (recommended)
./run-config-tests.sh

# Generate HTML report
./run-config-tests.sh html

# Or run tests directly in the tests directory
cd tests/config-parser
make test-config-full
```

**Docker-based Testing (recommended for consistency):**
```bash
# Run in Docker environment
docker exec ucentral_client_build_env bash -c \
  "cd /root/ols-nos/tests/config-parser && make test-config-full"
```

## Test Framework

The testing framework validates configurations through two layers:

1. **Schema Validation** - JSON structure validation against uCentral schema
2. **Parser Testing** - Actual C parser implementation testing with property tracking

Tests are organized in the `tests/` directory:
- `tests/config-parser/` - Configuration parser tests
- `tests/schema/` - Schema validation
- `tests/tools/` - Property database generation tools
- `tests/unit/` - Unit tests

## Documentation

- **[TESTING_FRAMEWORK.md](TESTING_FRAMEWORK.md)** - Testing overview and quick reference
- **[tests/README.md](tests/README.md)** - Complete testing documentation
- **[tests/config-parser/TEST_CONFIG_README.md](tests/config-parser/TEST_CONFIG_README.md)** - Detailed testing guide
- **[tests/MAINTENANCE.md](tests/MAINTENANCE.md)** - Schema and property database maintenance

## Test Configuration

Test configurations are located in `config-samples/`:
- 21 positive test configurations covering various features
- 4 negative test configurations for error handling validation
- JSON schema: `config-samples/ucentral.schema.pretty.json`

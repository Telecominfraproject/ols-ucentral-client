# PKI2.0 test
1. First, you need to use the openlan-pki-tools to generate the device birth certificate and register device on cloud discovery service:
  - cas.pem
  - cert.pem
  - cert.id
  - key.pem

2. Put the above four files into the following directory of the device:
  - /etc/ucentral/certs/

3. get or renew operational certificate, There are three ways:
  3.1  manually update the certificate
    - sonic# system bash 
      sudo est_client cacerts
      sudo est_client enroll
      sudo est_client reenroll

  3.2 Do nothing. The ucentral-client will automatically update the operational certificate.

4. Under normal circumstances, the device should be able to connect to the controller. If not, please perform the following operations:
  - sonic# configure 
    sonic(config)# no ucentral-client enable 
    sonic(config)# ucentral-client enable

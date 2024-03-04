This dir holds a few config-samples, that can be pushed (manually) from GW
web UI, and the uCentral application (running on SONiC NOS Switch device)
is capable of applying CFG stored in these json on the underlying HW.

cfg0:
  Simple put all Switchports down (admin state).
cfg1:
  Bring ports 1 and 2 (Ethernet1, Ethernet2) up (admin state)
cfg2:
  Bring ports 1 up, 2 down (Ethernet1, Ethernet2) (admin state)
cfg3:
  Bring ports 1 up, 2 up (Ethernet1, Ethernet2) (admin state);
  Destroy any VLAN that is not in the list (in this particular CFG - create VLAN 10,
    destroy any other, except for MGMT VLAN 1 - it's not being altered by the
    uCentral app itself);
  Create VLAN 10;
  Set VLAN 10 memberlist with the following ports: Ethernet1, Ethernet2;
  VLAN tagging for both ports is <tagged>;
cfg4:
  Bring ports 1 up, 2 up (Ethernet1, Ethernet2) (admin state);
  Destroy any VLAN that is not in the list (in this particular CFG - create VLAN 10, 100,
    destroy any other, except for MGMT VLAN 1 - it's not being altered by the
    uCentral app itself);
  Create VLAN 10;
  Create VLAN 100;
  Set VLAN 10 memberlist with the following ports: Ethernet1;
  Set VLAN 100 memberlist with the following ports: Ethernet2;
  VLAN tagging for both ports is <tagged>;

cfg5_poe:
  NOTE: all of the following values are default ones

  Configure device's global PoE cfg:
    - power-management is set to dynamic;
    - usage-threshold is set to 90 (%);
  Configuration applied to each PoE port (wildcard ethernet-select):
    - admin mode is UP (enabled);
    - no PoE port reset is requested;
    - detection mode is 4pt-dot3af;
    - power limit is 99900mW (e.g. max per port);
    - priority is LOW;

cfg7_ieee80211x.json:
  Following json file configures the given topology:
                                   +-----------------+
                                   |     Cloud1      |
                                   +-------+---------+
                                           |
                                           |eth0
+-----------------+                +-------+---------+                +----------------+
|   UBUNTU 16.04  |     VLAN50     |     SWITCH      |      VLAN20    |   FREERADIUS   |
|   (.1x client)  +----------------+  (authenticator)+----------------+     server     |
+-----------------+10.10.50.100/24 +-----------------+ 10.10.20.100/24+----------------+

  eth0 (mgmt port, enabled by default) is used to access internet / GW / cloud;
  VLAN50 (Ethernet5) connects Switch and ubuntu (.1x) client on 10.10.50.0/24 network;
  VLAN20 (Ethernet2) is a RADIUS (FREERADIUS) server on 10.10.20.0/24 network;
  Members of VLAN50 (Ethernet5) are configured to process EAPs and forward
  auth requests to FREERADIUS (intervlan routing);
  Unauthorized / unauthenticated vlans are configured for the completeness of cfg,
  and are not used in the setup above (simple L2 'loopback' switch can be added,
  to monitor traffic of guest / unauth vid if needed).
  Shared key (betweed FREERADIUS server and SWITCH) is configured to be 'abc10'.
  Key should be configured on both switch (this json cfg) and freeradius server
  to be the same for the given (10.10.20.0/24) network.
  .1x client also must have a valid credentials data (both client and radius server
  must have same clients credentials configured).

cfg_igmp.json:
  Configure igmp snooping and querier on VLAN 1.
  Configure igmp static groups:
    - 230.1.1.1 with egress port Ethernet1
    - 230.2.2.2 with egress ports Ethernet2 & Ethernet3

cfg_rpvstp.json:
  Configure VLAN 1;
  Configure VLAN 2;
  Configure rapid per-vlan STP on VLAN 1 with priority 32768;
  Disable STP on VLAN 2.

cfg_port_isolation.json:
  Configure port isolation with Ethernet1 as uplink and
  Ethernet2 & Ethernet3 as downlink

cfg_services_log.json:
  Enable syslog with these parameters:
  - remote host addr
  - remote host port
  - log severity (priority):
    * emerg: 0
    * alert: 1
    * crit: 2
    * error: 3
    * warning: 4
    * notice: 5
    * info: 6
    * debug: 7

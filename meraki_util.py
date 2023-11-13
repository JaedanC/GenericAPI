import meraki
import os
from .api import cache_csv, cache_json
from typing import List


ONE_DAY = 86400
ONE_MONTH = ONE_DAY * 31


if not os.path.exists("cache"):
    os.mkdir("cache")


if not os.path.exists("logs"):
    os.mkdir("logs")


def init(apikey: str) -> meraki.DashboardAPI:
    return meraki.DashboardAPI(apikey, print_console=False, log_file_prefix="logs/")


def listify(object):
    if isinstance(object, list):
        return object
    return [object]


@cache_json("cache/getOrganizations.json")
def get_organizations(dashboard: meraki.DashboardAPI):
    """https://developer.cisco.com/meraki/api-v1/get-organizations/
    ```json
    [
        {
            "id": "2930418",
            "name": "My organization",
            "url": "https://dashboard.meraki.com/o/VjjsAd/manage/organization/overview",
            "api": { "enabled": true },
            "licensing": { "model": "co-term" },
            "cloud": {
                "region": {
                    "name": "North America"
                }
            },
            "management": {
                "details": [
                    {
                        "name": "MSP ID",
                        "value": "123456"
                    }
                ]
            }
        }
    ]
    ```
    """
    return dashboard.organizations.getOrganizations()


@cache_json("cache/getOrganizationNetworks.json")
@cache_csv("cache/getOrganizationNetworks.csv")
def get_organization_networks(
    dashboard: meraki.DashboardAPI, organization_id: int) -> List[dict]:
    """https://developer.cisco.com/meraki/api-v1/get-organization-networks/
    ```json
    [
        {
            "id": "N_24329156",
            "organizationId": "2930418",
            "name": "Main Office",
            "productTypes": [
                "appliance",
                "switch",
                "wireless"
            ],
            "timeZone": "America/Los_Angeles",
            "tags": [ "tag1", "tag2" ],
            "enrollmentString": "my-enrollment-string",
            "url": "https://n1.meraki.com//n//manage/nodes/list",
            "notes": "Additional description of the network",
            "isBoundToConfigTemplate": false
        }
    ]
    ```
    """
    return dashboard.organizations.getOrganizationNetworks(organization_id)


@cache_json("cache/getNetworkClients.json", verbose=False)
@cache_csv("cache/getNetworkClients.csv", verbose=False)
def get_network_clients(
    dashboard: meraki.DashboardAPI, network_ids: List[str] | str, timespan):
    """https://developer.cisco.com/meraki/api-v1/get-network-clients/
    ```json
    [
        {
            "id": "k74272e",
            "mac": "22:33:44:55:66:77",
            "ip": "1.2.3.4",
            "ip6": "2001:db8:3c4d:15::1",
            "description": "Miles's phone",
            "firstSeen": 1518365681,
            "lastSeen": 1526087474,
            "manufacturer": "Apple",
            "os": "iOS",
            "user": "milesmeraki",
            "vlan": "100",
            "ssid": "My SSID",
            "switchport": "My switch port",
            "wirelessCapabilities": "802.11b - 2.4 GHz",
            "smInstalled": true,
            "recentDeviceMac": "22:33:44:55:66:77",
            "status": "Online",
            "usage": { "sent": 138, "recv": 61 },
            "namedVlan": "My VLAN",
            "adaptivePolicyGroup": "2: Infrastructure",
            "deviceTypePrediction": "iPhone SE, iOS9.3.5",
            "recentDeviceSerial": "00:11:22:33:44:55",
            "recentDeviceName": "Q234-ABCD-5678",
            "recentDeviceConnection": "Wired",
            "notes": "My AP's note",
            "ip6Local": "fe80:0:0:0:1430:aac1:6826:75ab",
            "groupPolicy8021x": "Student_Access",
            "pskGroup": "Group 1"
        }
    ]
    ```
    """
    network_ids = listify(network_ids)
    
    all_clients = []
    for network_id in network_ids:
        try:
            network_clients = dashboard.networks.getNetworkClients(
                network_id,
                total_pages="all",
                perPage=500,
                timespan=timespan
            )
        except meraki.exceptions.APIError as e:
            print(e)
            continue

        for client in network_clients:
            client: dict
            client.update({"network_id": network_id})
            all_clients.append(client)
    
    return all_clients


@cache_json("cache/getOrganizationApplianceUplinkStatuses.json")
@cache_csv("cache/getOrganizationApplianceUplinkStatuses.csv")
def get_organization_appliance_uplink_statuses(
    dashboard: meraki.DashboardAPI, organization_id: int):
    """https://developer.cisco.com/meraki/api-v1/get-organization-uplinks-statuses/
    ```json
    [
        {
            "networkId": "N_24329156",
            "serial": "Q234-ABCD-5678",
            "model": "MX68C",
            "lastReportedAt": "2018-02-11T00:00:00Z",
            "uplinks": [
                {
                    "interface": "wan1",
                    "status": "active",
                    "ip": "1.2.3.4",
                    "gateway": "1.2.3.5",
                    "publicIp": "123.123.123.1",
                    "primaryDns": "8.8.8.8",
                    "secondaryDns": "8.8.4.4",
                    "ipAssignedBy": "static",
                    "provider": "at&t",
                    "signalStat": {
                        "rsrp": "-120",
                        "rsrq": "-13"
                    },
                    "connectionType": "4g",
                    "apn": "internet",
                    "dns1": "111.111.111.111",
                    "dns2": "222.222.222.222",
                    "signalType": "4G",
                    "iccid": "123456789"
                }
            ]
        }
    ]
    ```
    """
    return dashboard.appliance.getOrganizationApplianceUplinkStatuses(organization_id, "all")


@cache_json("cache/getOrganizationDevicesPowerModulesStatusesByDevice.json")
def get_organization_devices_power_modules_statuses_by_device(
    dashboard: meraki.DashboardAPI, organization_id: int, **kwargs):
    """https://developer.cisco.com/meraki/api-latest/get-organization-devices-power-modules-statuses-by-device/
    ```json
    [
        {
            "mac": "00:11:22:33:44:55",
            "name": "My AP",
            "network": { "id": "N_24329156" },
            "productType": "switch",
            "serial": "Q234-ABCD-5678",
            "tags": [ "tag1", "tag2" ],
            "slots": [
                {
                    "number": 1,
                    "serial": "Q234-ABCD-5678",
                    "model": "PWR-C5-125WAC",
                    "status": "not connected"
                }
            ]
        }
    ]
    ```
    """
    return dashboard.organizations.getOrganizationDevicesPowerModulesStatusesByDevice(organization_id, "all", **kwargs)


@cache_json("cache/getDeviceApplianceDhcpSubnets.json")
def get_device_appliance_dhcp_subnets(
    dashboard: meraki.DashboardAPI, serial: str):
    """https://developer.cisco.com/meraki/api-latest/get-device-appliance-dhcp-subnets/
    ```json
    [
        {
            "subnet": "192.168.1.0/24",
            "vlanId": 100,
            "usedCount": 2,
            "freeCount": 251
        }
    ]
    ```
    """
    return dashboard.appliance.getDeviceApplianceDhcpSubnets(serial)


@cache_json("cache/getDeviceClients.json")
@cache_csv("cache/getDeviceClients.csv")
def get_device_clients(dashboard: meraki.DashboardAPI, serial: str):
    """https://developer.cisco.com/meraki/api-latest/get-device-appliance-dhcp-subnets/
    ```json
    [
        {
            "usage": { "sent": 138, "recv": 61 },
            "id": "k74272e",
            "description": "Miles's phone",
            "mac": "22:33:44:55:66:77",
            "ip": "1.2.3.4",
            "user": "milesmeraki",
            "vlan": "255",
            "namedVlan": "Named Vlan",
            "switchport": null,
            "adaptivePolicyGroup": null,
            "mdnsName": "Miles's phone",
            "dhcpHostname": "MilesPhone"
        }
    ]
    ```
    """
    return dashboard.devices.getDeviceClients(serial)


@cache_json("cache/getDeviceApplianceUplinksSettings.json")
def get_device_appliance_uplinks_settings(
    dashboard: meraki.DashboardAPI, serial: str):
    """https://developer.cisco.com/meraki/api/get-device-appliance-uplinks-settings/
    ```json
    {
        "interfaces": {
            "wan1": {
                "enabled": true,
                "vlanTagging": {
                    "enabled": true,
                    "vlanId": 1
                },
                "svis": {
                    "ipv4": {
                        "assignmentMode": "static",
                        "address": "9.10.11.10/16",
                        "gateway": "13.14.15.16",
                        "nameservers": {
                            "addresses": [
                                "1.2.3.4"
                            ]
                        }
                    },
                    "ipv6": {
                        "assignmentMode": "static",
                        "address": "1:2:3::4",
                        "gateway": "1:2:3::5",
                        "nameservers": {
                            "addresses": [
                                "1001:4860:4860::8888",
                                "1001:4860:4860::8844"
                            ]
                        }
                    }
                },
                "pppoe": {
                    "enabled": true,
                    "authentication": {
                        "enabled": true,
                        "username": "username"
                    }
                }
            },
            "wan2": {
                "enabled": true,
                "vlanTagging": {
                    "enabled": true,
                    "vlanId": 1
                },
                "svis": {
                    "ipv4": {
                        "assignmentMode": "static",
                        "address": "9.10.11.10/16",
                        "gateway": "13.14.15.16",
                        "nameservers": {
                            "addresses": [
                                "1.2.3.4"
                            ]
                        }
                    },
                    "ipv6": {
                        "assignmentMode": "static",
                        "address": "1:2:3::4",
                        "gateway": "1:2:3::5",
                        "nameservers": {
                            "addresses": [
                                "1001:4860:4860::8888",
                                "1001:4860:4860::8844"
                            ]
                        }
                    }
                },
                "pppoe": {
                    "enabled": true,
                    "authentication": {
                        "enabled": true,
                        "username": "username"
                    }
                }
            }
        }
    }
    ```
    """
    return dashboard.appliance.getDeviceApplianceUplinksSettings(serial)


@cache_json("cache/getNetworkApplianceVlans.json", verbose=False)
def get_network_appliance_vlans(
    dashboard: meraki.DashboardAPI, network_id: str):
    """https://developer.cisco.com/meraki/api/get-network-appliance-vlans/
    ```json
    [
        {
            "id": "1234",
            "interfaceId": "1284392014819",
            "name": "My VLAN",
            "subnet": "192.168.1.0/24",
            "applianceIp": "192.168.1.2",
            "groupPolicyId": "101",
            "templateVlanType": "same",
            "cidr": "192.168.1.0/24",
            "mask": 28,
            "dhcpRelayServerIps": [
                "192.168.1.0/24",
                "192.168.128.0/24"
            ],
            "dhcpHandling": "Run a DHCP server",
            "dhcpLeaseTime": "1 day",
            "dhcpBootOptionsEnabled": false,
            "dhcpBootNextServer": "1.2.3.4",
            "dhcpBootFilename": "sample.file",
            "reservedIpRanges": [
                {
                    "start": "192.168.1.0",
                    "end": "192.168.1.1",
                    "comment": "A reserved IP range"
                }
            ],
            "dnsNameservers": "google_dns",
            "dhcpOptions": [
                {
                    "code": "5",
                    "type": "text",
                    "value": "five"
                }
            ],
            "vpnNatSubnet": "192.168.1.0/24",
            "mandatoryDhcp": { "enabled": true },
            "ipv6": {
                "enabled": true,
                "prefixAssignments": [
                    {
                        "autonomous": false,
                        "staticPrefix": "2001:db8:3c4d:15::/64",
                        "staticApplianceIp6": "2001:db8:3c4d:15::1",
                        "origin": {
                            "type": "internet",
                            "interfaces": [ "wan0" ]
                        }
                    }
                ]
            }
        }
    ]
    ```
    """
    return dashboard.appliance.getNetworkApplianceVlans(network_id)


@cache_json("cache/getNetworkApplianceSingleLan.json", verbose=False)
def get_network_appliance_single_lan(
        dashboard: meraki.DashboardAPI, network_id: str):
    """https://developer.cisco.com/meraki/api/get-network-appliance-single-lan/
    ```json
    {
        "subnet": "192.168.1.0/24",
        "applianceIp": "192.168.1.2",
        "mandatoryDhcp": { "enabled": true },
        "ipv6": {
            "enabled": true,
            "prefixAssignments": [
                {
                    "autonomous": false,
                    "staticPrefix": "2001:db8:3c4d:15::/64",
                    "staticApplianceIp6": "2001:db8:3c4d:15::1",
                    "origin": {
                        "type": "internet",
                        "interfaces": [ "wan0" ]
                    }
                }
            ]
        }
    }
    ```
    """
    return dashboard.appliance.getNetworkApplianceSingleLan(network_id)



@cache_json("cache/getNetworkDevices.json")
def get_network_devices(dashboard: meraki.DashboardAPI, network_id: str):
    """https://developer.cisco.com/meraki/api/get-network-devices/
    ```json
    [
        {
            "name": "My AP",
            "lat": 37.4180951010362,
            "lng": -122.098531723022,
            "serial": "Q234-ABCD-5678",
            "mac": "00:11:22:33:44:55",
            "model": "MR34",
            "address": "1600 Pennsylvania Ave",
            "notes": "My AP's note",
            "lanIp": "1.2.3.4",
            "tags": " recently-added ",
            "networkId": "N_24329156",
            "beaconIdParams": {
                "uuid": "00000000-0000-0000-0000-000000000000",
                "major": 5,
                "minor": 3
            },
            "firmware": "wireless-25-14",
            "floorPlanId": "g_1234567"
        }
    ]
    ```
    """
    return dashboard.networks.getNetworkDevices(network_id)

 
@cache_json("cache/getOrganizationApplianceVpnThirdPartyVPNPeers.json")
def get_organization_appliance_vpn_third_party_vpn_peers(
    dashboard: meraki.DashboardAPI, organization_id: str):
    """https://developer.cisco.com/meraki/api/get-organization-appliance-vpn-third-party-vpn-peers/
    ```json
    {
        "peers": [
            {
                "name": "Peer Name",
                "publicIp": "123.123.123.1",
                "remoteId": "miles@meraki.com",
                "localId": "myMXId@meraki.com",
                "secret": "secret",
                "privateSubnets": [
                    "192.168.1.0/24",
                    "192.168.128.0/24"
                ],
                "ipsecPolicies": {
                    "ikeCipherAlgo": [ "tripledes" ],
                    "ikeAuthAlgo": [ "sha1" ],
                    "ikePrfAlgo": [ "prfsha1" ],
                    "ikeDiffieHellmanGroup": [ "group2" ],
                    "ikeLifetime": 28800,
                    "childCipherAlgo": [ "aes128" ],
                    "childAuthAlgo": [ "sha1" ],
                    "childPfsGroup": [ "disabled" ],
                    "childLifetime": 28800
                },
                "ipsecPoliciesPreset": "custom",
                "ikeVersion": "1",
                "networkTags": [ "all" ]
            }
        ]
    }
    ```
    """
    return dashboard.appliance.getOrganizationApplianceVpnThirdPartyVPNPeers(organization_id)


@cache_json("cache/getNetworkApplianceVpnSiteToSiteVpn.json", verbose=False)
def get_network_appliance_vpn_site_to_site_vpn(
    dashboard: meraki.DashboardAPI, network_id: str):
    """https://developer.cisco.com/meraki/api/get-network-appliance-vpn-site-to-site-vpn/
    ```json
    {
        "mode": "spoke",
        "hubs": [
            {
                "hubId": "N_4901849",
                "useDefaultRoute": true
            }
        ],
        "subnets": [
            {
                "localSubnet": "192.168.1.0/24",
                "useVpn": true
            }
        ]
    }
    ```
    """
    return dashboard.appliance.getNetworkApplianceVpnSiteToSiteVpn(network_id)


@cache_json("cache/getDeviceCellularSims.json", verbose=False)
def get_device_cellular_sims(
    dashboard: meraki.DashboardAPI, serial: str):
    """https://developer.cisco.com/meraki/api/get-device-cellular-sims/
    {
        "sims": [
            {
                "slot": "sim1",
                "isPrimary": true,
                "apns": [
                    {
                        "name": "internet",
                        "allowedIpTypes": [
                            "ipv4",
                            "ipv6"
                        ],
                        "authentication": {
                            "type": "pap",
                            "username": "milesmeraki"
                        }
                    }
                ]
            }
        ]
    }
    """
    return dashboard.devices.getDeviceCellularSims(serial)


@cache_json("cache/getNetworkApplianceStaticRoutes.json", verbose=False)
def get_network_appliance_static_routes(
    dashboard: meraki.DashboardAPI, network_id: str) -> List[dict]:
    """https://developer.cisco.com/meraki/api/get-network-appliance-static-routes/
    [
        {
            "id": "d7fa4948-7921-4dfa-af6b-ae8b16c20c39",
            "ipVersion": 4,
            "networkId": "N_24329156",
            "enabled": true,
            "name": "My route",
            "subnet": "192.168.1.0/24",
            "gatewayIp": "1.2.3.5",
            "fixedIpAssignments": {
                "22:33:44:55:66:77": {
                    "ip": "1.2.3.4",
                    "name": "Some client name"
                }
            },
            "reservedIpRanges": [
                {
                    "start": "192.168.1.0",
                    "end": "192.168.1.1",
                    "comment": "A reserved IP range"
                }
            ],
            "gatewayVlanId": 100
        }
    ]
    """
    return dashboard.appliance.getNetworkApplianceStaticRoutes(network_id)


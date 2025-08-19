from typing import List
import json
import os

import requests
import meraki
from .api import cache_csv, cache_json


ONE_DAY = 86400
ONE_MONTH = ONE_DAY * 31


if not os.path.exists("cache"):
    os.mkdir("cache")


if not os.path.exists("logs"):
    os.mkdir("logs")


def init(apikey: str) -> meraki.DashboardAPI:
    return meraki.DashboardAPI(apikey, print_console=False, log_file_prefix="logs/")


def listify(obj):
    if isinstance(obj, list):
        return obj
    return [obj]


# @cache_json("cache/getOrganizations.json")
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


# @cache_json("cache/getOrganizationNetworks.json")
# @cache_csv("cache/getOrganizationNetworks.csv")
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


# @cache_json("cache/getNetwork.json", verbose=False)
def get_network(
    dashboard: meraki.DashboardAPI, network_id: str):
    """https://developer.cisco.com/meraki/api-v1/get-network/
    ```json
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
    ```
    """
    return dashboard.networks.getNetwork(network_id)


# @cache_json("cache/getNetworkClients.json", verbose=False)
# @cache_csv("cache/getNetworkClients.csv", verbose=False)
def get_network_clients(
    dashboard: meraki.DashboardAPI, networks: List[dict], timespan):
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
    networks = listify(networks)
    networks.sort(key=lambda n: n["name"])

    all_clients = []
    for i, network in enumerate(networks):
        print("{}/{}: {}".format(i + 1, len(networks), network["name"]))
        try:
            network_clients = dashboard.networks.getNetworkClients(
                network["id"],
                total_pages="all",
                perPage=500,
                timespan=timespan
            )
        except meraki.exceptions.APIError as e:
            print(e)
            continue

        for client in network_clients:
            client: dict
            client.update({
                "network_id": network["id"],
                "network":    network["name"],
            })
            all_clients.append(client)

    return all_clients


# @cache_json("cache/getOrganizationWebhooksHttpServers.json")
def get_organization_webhooks_http_servers(
        MERAKI_API_KEY: str,
        organization_id: str
    ) -> List[dict]:
    """https://developer.cisco.com/meraki/api-v1/get-organization-webhooks-http-servers/
    ```json
    [
        {
            "id": "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20vbXlfY3VzdG9tX3dlYmhvb2s=",
            "name": "Example Webhook Server",
            "organizationId": "2930418",
            "url": "https://www.example.com/my_custom_webhook",
            "payloadTemplate": {
                "id": "wpt_00001",
                "name": "Meraki (included)"
            }
        }
    ]
    ```
    """
    url = f"https://api.meraki.com/api/v1/organizations/{organization_id}/webhooks/httpServers"

    payload = None
    headers = {
        "Authorization": "Bearer " + MERAKI_API_KEY,
        "Accept": "application/json"
    }
    response = requests.request('GET', url, headers=headers, data = payload, timeout=60)
    return json.loads(response.text.encode("utf-8"))


# @cache_json("cache/getNetworkWebhooksHttpServers.json")
def get_network_webhooks_http_servers(
    dashboard: meraki.DashboardAPI, network_id: str):
    """https://developer.cisco.com/meraki/api-v1/get-network-webhooks-http-servers/
    ```json
    [
        {
            "id": "aHR0cHM6Ly93d3cuZXhhbXBsZS5jb20vbXlfY3VzdG9tX3dlYmhvb2s=",
            "name": "Example Webhook Server",
            "url": "https://www.example.com/my_custom_webhook",
            "networkId": "N_12345678",
            "payloadTemplate": {
                "payloadTemplateId": "wpt_00001",
                "name": "Meraki (included)"
            }
        }
    ]
    ```
    """
    return dashboard.networks.getNetworkWebhooksHttpServers(network_id)


# @cache_json("cache/getOrganizationApplianceUplinkStatuses.json")
# @cache_csv("cache/getOrganizationApplianceUplinkStatuses.csv")
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


# @cache_json("cache/getOrganizationDevicesPowerModulesStatusesByDevice.json")
def get_organization_devices_power_modules_statuses_by_device(
        dashboard: meraki.DashboardAPI,
        organization_id: int,
        **kwargs,
    ):
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
    return dashboard.organizations.getOrganizationDevicesPowerModulesStatusesByDevice(
        organization_id,
        "all",
        **kwargs
    )


# @cache_json("cache/getDeviceApplianceDhcpSubnets.json")
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


# @cache_json("cache/getDeviceClients.json")
# @cache_csv("cache/getDeviceClients.csv")
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


# @cache_json("cache/getDeviceApplianceUplinksSettings.json")
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


# @cache_json("cache/getDeviceSwitchPortsStatuses.json")
def get_device_switch_ports_statuses(dashboard: meraki.DashboardAPI, serial: str, **kwargs):
    """https://developer.cisco.com/meraki/api-v1/get-device-switch-ports-statuses/
    ```json
    [
        {
            "portId": "1",
            "enabled": true,
            "status": "Connected",
            "spanningTree": {
                "statuses": [ "Learning" ]
            },
            "isUplink": false,
            "errors": [
                "PoE overload",
                "Very high proportion of CRC errors"
            ],
            "warnings": [
                "SecurePort authentication in progress",
                "PoE port was denied power",
                "High proportion of CRC errors"
            ],
            "speed": "10 Gbps",
            "duplex": "full",
            "usageInKb": {
                "total": 40867,
                "sent": 23008,
                "recv": 17859
            },
            "cdp": {
                "systemName": "",
                "platform": "MS350-24X",
                "deviceId": "0c8ddbddee:ff",
                "portId": "Port 20",
                "nativeVlan": 1,
                "address": "10.0,0.1",
                "managementAddress": "10.0.0.100",
                "version": "1",
                "vtpManagementDomain": "",
                "capabilities": "Switch"
            },
            "lldp": {
                "systemName": "MS350-24X - Test",
                "systemDescription": "MS350-24X Cloud Managed PoE Switch",
                "chassisId": "0c:8d:db:dd:ee:ff",
                "portId": "20",
                "managementVlan": 1,
                "portVlan": 1,
                "managementAddress": "10.0.0.100",
                "portDescription": "Port 20",
                "systemCapabilities": "switch"
            },
            "clientCount": 10,
            "powerUsageInWh": 55.9,
            "trafficInKbps": {
                "total": 2.2,
                "sent": 1.2,
                "recv": 1
            },
            "securePort": {
                "enabled": true,
                "active": true,
                "authenticationStatus": "Authentication in progress",
                "configOverrides": {
                    "type": "trunk",
                    "vlan": 12,
                    "voiceVlan": 34,
                    "allowedVlans": "all"
                }
            },
            "poe": { "isAllocated": false }
        }
    ]
    ```
    """
    return dashboard.switch.getDeviceSwitchPortsStatuses(serial, **kwargs)


# @cache_json("cache/getNetworkAppliancePorts,json", verbose=False)
def get_network_appliance_ports(
    dashboard: meraki.DashboardAPI, network_id: str):
    """https://developer.cisco.com/meraki/api-v1/get-network-appliance-ports/
    ```json
    [
        {
            "number": 1,
            "enabled": true,
            "type": "access",
            "dropUntaggedTraffic": false,
            "vlan": 3,
            "allowedVlans": "all",
            "accessPolicy": "open"
        }
    ]
    ```
    """
    return dashboard.appliance.getNetworkAppliancePorts(network_id)


# @cache_json("cache/getNetworkApplianceVlans.json", verbose=False)
def get_network_appliance_vlans(
    dashboard: meraki.DashboardAPI, network_id: str):
    """https://developer.cisco.com/meraki/api-v1/get-network-appliance-vlans/
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


# @cache_json("cache/getNetworkApplianceSingleLan.json", verbose=False)
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


# @cache_json("cache/getNetworkDevices.json")
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


# @cache_json("cache/getOrganizationApplianceVpnThirdPartyVPNPeers.json")
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


# @cache_json("cache/getNetworkApplianceVpnSiteToSiteVpn.json", verbose=False)
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


# @cache_json("cache/getDeviceCellularSims.json", verbose=False)
def get_device_cellular_sims(
    dashboard: meraki.DashboardAPI, serial: str):
    """https://developer.cisco.com/meraki/api/get-device-cellular-sims/
    ```json
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
    ```
    """
    return dashboard.devices.getDeviceCellularSims(serial)


# @cache_json("cache/getNetworkApplianceStaticRoutes.json", verbose=False)
def get_network_appliance_static_routes(
    dashboard: meraki.DashboardAPI, network_id: str) -> List[dict]:
    """https://developer.cisco.com/meraki/api/get-network-appliance-static-routes/
    ```json
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
    ```
    """
    return dashboard.appliance.getNetworkApplianceStaticRoutes(network_id)


# @cache_json("cache/getDeviceLldpCdp.json")
def get_device_lldp_cdp(
    dashboard: meraki.DashboardAPI, serial: str) -> dict:
    """https://developer.cisco.com/meraki/api/get-device-lldp-cdp/
    ```json
    {
        "sourceMac": "00:11:22:33:44:55",
        "ports": {
            "8": {
                "cdp": {
                    "deviceId": "e0553d8cdf53",
                    "portId": "Port 10",
                    "address": "00:11:22:33:44:55",
                    "sourcePort": "8"
                }
            },
            "12": {
                "cdp": {
                    "deviceId": "e0553d8cdf53",
                    "portId": "Port 11",
                    "address": "00:11:22:33:44:55",
                    "sourcePort": "12"
                },
                "lldp": {
                    "systemName": "Meraki MS350-24X - Phineas",
                    "portId": "11",
                    "managementAddress": "00:11:22:33:44:55",
                    "sourcePort": "12"
                }
            }
        }
    }
    ```
    """
    return dashboard.devices.getDeviceLldpCdp(
        serial
    )


@cache_json("cache/getOrganizationDevices.json")
# @cache_csv("cache/getOrganizationDevices.csv")
def get_organization_devices(
        dashboard: meraki.DashboardAPI, organization_id: str, **kwargs) -> dict:
    """https://developer.cisco.com/meraki/api-v1/get-organization-devices/
    ```json
    [
        {
            "name": "My AP",
            "lat": 37.4180951010362,
            "lng": -122.098531723022,
            "address": "1600 Pennsylvania Ave",
            "notes": "My AP's note",
            "tags": [ "recently-added" ],
            "networkId": "N_24329156",
            "serial": "Q234-ABCD-5678",
            "model": "MR34",
            "imei": "123456789000000",
            "mac": "00:11:22:33:44:55",
            "lanIp": "1.2.3.4",
            "firmware": "wireless-25-14",
            "productType": "wireless",
            "details": [
                {
                    "name": "Catalyst serial",
                    "value": "123ABC"
                }
            ]
        }
    ]
    ```
    """
    return dashboard.organizations.getOrganizationDevices(
        organization_id,
        "all",
        **kwargs
    )


# @cache_json("cache/getNetworkApplianceFirewallCellularFirewallRules.json")
def get_network_appliance_firewall_cellular_firewall_rules(
    dashboard: meraki.DashboardAPI, network_id: str) -> dict:
    """https://developer.cisco.com/meraki/api-v1/get-network-appliance-firewall-cellular-firewall-rules/
    ```json
    {
        "rules": [
            {
                "comment": "Allow TCP traffic to subnet with HTTP servers.",
                "policy": "allow",
                "protocol": "tcp",
                "destPort": "443",
                "destCidr": "192.168.1.0/24",
                "srcPort": "Any",
                "srcCidr": "Any",
                "syslogEnabled": false
            }
        ]
    }
    ```
    """
    return dashboard.appliance.getNetworkApplianceFirewallCellularFirewallRules(
        network_id
    )


# @cache_json("cache/getOrganizationConfigTemplates.json")
def get_organization_config_templates(
    dashboard: meraki.DashboardAPI, organization_id: str):
    """https://developer.cisco.com/meraki/api/get-organization-config-templates/
    ```json
    [
        {
            "id": "N_24329156",
            "name": "My config template",
            "productTypes": [
                "appliance",
                "switch",
                "wireless"
            ],
            "timeZone": "America/Los_Angeles"
        }
    ]
    ```
    """
    return dashboard.organizations.getOrganizationConfigTemplates(
        organization_id
    )


# @cache_json("cache/getDeviceSwitchRoutingInterfaces.json")
def get_device_switch_routing_interfaces(
    dashboard: meraki.DashboardAPI, serial: str):
    """https://developer.cisco.com/meraki/api-v1/get-device-switch-routing-interfaces/
    ```json
    [
        {
            "interfaceId": "1234",
            "name": "L3 interface",
            "subnet": "192.168.1.0/24",
            "interfaceIp": "192.168.1.2",
            "multicastRouting": "disabled",
            "vlanId": 100,
            "defaultGateway": "192.168.1.1",
            "ospfSettings": {
                "area": "0",
                "cost": 1,
                "isPassiveEnabled": true
            },
            "ospfV3": {
                "area": "1",
                "cost": 2,
                "isPassiveEnabled": true
            },
            "ipv6": {
                "assignmentMode": "static",
                "address": "1:2:3:4::1",
                "prefix": "1:2:3:4::/48",
                "gateway": "1:2:3:4::2"
            }
        }
    ]
    ```
    """
    return dashboard.switch.getDeviceSwitchRoutingInterfaces(
        serial
    )


@cache_json("cache/getDeviceSwitchPorts.json")
def get_device_switch_ports(
    dashboard: meraki.DashboardAPI, serial: str):
    """https://developer.cisco.com/meraki/api-v1/get-device-switch-ports/
    ```json
    [
        {
            "portId": "1",
            "name": "My switch port",
            "tags": [ "tag1", "tag2" ],
            "enabled": true,
            "poeEnabled": true,
            "type": "access",
            "vlan": 10,
            "voiceVlan": 20,
            "allowedVlans": "1,3,5-10",
            "isolationEnabled": false,
            "rstpEnabled": true,
            "stpGuard": "disabled",
            "linkNegotiation": "Auto negotiate",
            "linkNegotiationCapabilities": [
                "Auto negotiate",
                "1 Gigabit full duplex (auto)"
            ],
            "portScheduleId": "1234",
            "udld": "Alert only",
            "accessPolicyType": "Sticky MAC allow list",
            "accessPolicyNumber": 2,
            "macAllowList": [
                "34:56:fe:ce:8e:b0",
                "34:56:fe:ce:8e:b1"
            ],
            "stickyMacAllowList": [
                "34:56:fe:ce:8e:b0",
                "34:56:fe:ce:8e:b1"
            ],
            "stickyMacAllowListLimit": 5,
            "stormControlEnabled": true,
            "adaptivePolicyGroupId": "123",
            "peerSgtCapable": false,
            "flexibleStackingEnabled": true,
            "daiTrusted": false,
            "profile": {
                "enabled": false,
                "id": "1284392014819",
                "iname": "iname"
            },
            "module": { "model": "MA-MOD-4X10G" },
            "mirror": {
                "mode": "Not mirroring traffic"
            }
        }
    ]
    ```
    """
    return dashboard.switch.getDeviceSwitchPorts(
        serial
    )


# @cache_json("cache/getNetworkSwitchStacks.json")
def get_network_switch_stacks(
        dashboard: meraki.DashboardAPI, network_id: str):
    """https://developer.cisco.com/meraki/api-v1/get-network-switch-stacks/
    ```json
    [
        {
            "id": "8473",
            "name": "A cool stack",
            "serials": [
                "QBZY-XWVU-TSRQ",
                "QBAB-CDEF-GHIJ"
            ]
        }
    ]
    ```
    """
    return dashboard.switch.getNetworkSwitchStacks(
        network_id
    )


# @cache_json("cache/getNetworkSwitchStackRoutingInterfaces.json")
def get_network_switch_stack_routing_interfaces(
        dashboard: meraki.DashboardAPI,
        network_id: str,
        switch_stack_id: str
    ):
    """https://developer.cisco.com/meraki/api-v1/get-network-switch-stack-routing-interfaces/
    ```json
    [
        {
            "interfaceId": "1234",
            "name": "L3 interface",
            "subnet": "192.168.1.0/24",
            "interfaceIp": "192.168.1.2",
            "multicastRouting": "disabled",
            "vlanId": 100,
            "defaultGateway": "192.168.1.1",
            "ospfSettings": {
                "area": "0",
                "cost": 1,
                "isPassiveEnabled": true
            },
            "ospfV3": {
                "area": "1",
                "cost": 2,
                "isPassiveEnabled": true
            },
            "ipv6": {
                "assignmentMode": "static",
                "address": "1:2:3:4::1",
                "prefix": "1:2:3:4::/48",
                "gateway": "1:2:3:4::2"
            }
        }
    ]
    ```
    """
    return dashboard.switch.getNetworkSwitchStackRoutingInterfaces(
        network_id,
        switch_stack_id
    )


# @cache_json("cache/getOrganizationSwitchPortsBySwitch.json")
def get_organization_switch_ports_by_switch(
        dashboard: meraki.DashboardAPI,
        organization_id: str,
    ):
    """https://developer.cisco.com/meraki/api/get-organization-switch-ports-by-switch/
    ```json
    [
        {
            "name": "Example Switch",
            "serial": "Q555-5555-5555",
            "mac": "01:23:45:67",
            "network": {
                "name": "Example Network",
                "id": "N_12345"
            },
            "model": "MS120-8",
            "ports": [
                {
                    "portId": "1",
                    "name": "My switch port",
                    "tags": [ "tag1", "tag2" ],
                    "enabled": true,
                    "poeEnabled": true,
                    "type": "access",
                    "vlan": 10,
                    "voiceVlan": 20,
                    "allowedVlans": "1,3,5-10",
                    "rstpEnabled": true,
                    "stpGuard": "disabled",
                    "linkNegotiation": "Auto negotiate",
                    "accessPolicyType": "Sticky MAC allow list",
                    "stickyMacAllowList": [
                        "34:56:fe:ce:8e:b0",
                        "34:56:fe:ce:8e:b1"
                    ],
                    "stickyMacAllowListLimit": 5
                }
            ]
        }
    ]
    ```
    """
    return dashboard.switch.getOrganizationSwitchPortsBySwitch(
        organization_id, total_pages='all'
    )


# @cache_json("cache/getNetworkClientsOverview.json")
# @cache_csv("cache/getNetworkClientsOverview.csv")
def get_network_clients_application_usage(
        dashboard: meraki.DashboardAPI,
        network_id: str,
        clients: List[str],
        **kwargs,
    ):
    """https://developer.cisco.com/meraki/api-v1/get-network-clients-application-usage/
    ```json
    [
        {
            "clientId": "k74272e",
            "clientIp": "1.2.3.4",
            "clientMac": "00:11:22:33:44:55",
            "applicationUsage": [
                {
                    "application": "Google",
                    "received": 383,
                    "sent": 56
                }
            ]
        }
    ]

    Modified to below
    [
        {
            "clientId": "k74272e",
            "clientIp": "1.2.3.4",
            "clientMac": "00:11:22:33:44:55",
            "application": "Google",
            "received": 383,
            "sent": 56
        }
    ]

    ```
    """
    client_usage_aggregated = []
    step = 80
    for i in range(0, len(clients), step):
        print("Querying clients: {} to {} of {}".format(i, i + step, len(clients)))
        client_usage_aggregated += dashboard.networks.getNetworkClientsApplicationUsage(
            network_id,
            ",".join(clients[i:i + step]),
            total_pages='all',
            **kwargs
        )

    unfolded = []
    for client in client_usage_aggregated:
        for application in client["applicationUsage"]:
            unfolded.append({
                "clientId":    client["clientId"],
                "clientIp":    client["clientIp"],
                "clientMac":   client["clientMac"],
                "application": application["application"],
                "received":    application["received"],
                "sent":        application["sent"],
            })

    return unfolded


# @cache_json("cache/getOrganizationApplianceUplinksUsageByNetwork.json")
def get_organization_appliance_uplinks_usage_by_network(
        dashboard: meraki.DashboardAPI,
        organization_id: str,
        **kwargs
    ) -> List[dict]:
    """
    https://developer.cisco.com/meraki/api-v1/get-organization-appliance-uplinks-usage-by-network/
    ```json
    [
        {
            "networkId": "N_24329156",
            "name": "Main Office",
            "byUplink": [
                {
                    "serial": "Q234-ABCD-5678",
                    "interface": "wan1",
                    "sent": 200,
                    "received": 400
                }
            ]
        }
    ]
    ```
    """
    return dashboard.appliance.getOrganizationApplianceUplinksUsageByNetwork(
        organization_id,
        **kwargs
    )

# @cache_json("cache/getNetworkApplianceUplinksUsageHistory.json")
def get_network_appliance_uplinks_usage_history(
        dashboard: meraki.DashboardAPI,
        network_id: str,
        **kwargs
    ):
    """
    https://developer.cisco.com/meraki/api-v1/get-network-appliance-uplinks-usage-history/
    ```json
    [
        {
            "startTime": "2021-07-22T02:00:00Z",
            "endTime": "2021-07-22T03:00:00Z",
            "byInterface": [
                {
                    "interface": "wan1",
                    "sent": 1562063,
                    "received": 9528787
                },
                {
                    "interface": "wan2",
                    "sent": 396646,
                    "received": 2747782
                }
            ]
        },
        {
            "startTime": "2021-07-22T03:00:00Z",
            "endTime": "2021-07-22T04:00:00Z",
            "byInterface": [
                {
                    "interface": "wan1",
                    "sent": 6326222,
                    "received": 12253346
                },
                {
                    "interface": "wan2",
                    "sent": 402850,
                    "received": 2981021
                }
            ]
        }
    ]
    ```
    """
    return dashboard.appliance.getNetworkApplianceUplinksUsageHistory(
        network_id,
        **kwargs
    )

# @cache_json("cache/getNetworkApplianceTrafficShapingUplinkBandwidth.json")
def get_network_appliance_traffic_shaping_uplink_bandwidth(
        dashboard: meraki.DashboardAPI,
        network_id: str,
    ):
    """
    https://developer.cisco.com/meraki/api-v1/get-network-appliance-traffic-shaping-uplink-bandwidth/
    ```json
    {
        "bandwidthLimits": {
            "wan1": {
                "limitUp": 1000000,
                "limitDown": 1000000
            },
            "wan2": {
                "limitUp": 1000000,
                "limitDown": 1000000
            },
            "cellular": {
                "limitUp": 51200,
                "limitDown": 51200
            }
        }
    }
    ```
    """
    return dashboard.appliance.getNetworkApplianceTrafficShapingUplinkBandwidth(
        network_id
    )


# @cache_json("cache/getNetworkWirelessSsids.json")
def get_network_wireless_ssids(
        dashboard: meraki.DashboardAPI,
        network_id: str,
    ):
    """
    https://developer.cisco.com/meraki/api-v1/get-network-wireless-ssids/
    ```json
    [
        {
            "number": 0,
            "name": "My SSID",
            "enabled": true,
            "splashPage": "Click-through splash page",
            "ssidAdminAccessible": false,
            "localAuth": false,
            "authMode": "8021x-radius",
            "encryptionMode": "wpa",
            "wpaEncryptionMode": "WPA2 only",
            "radiusServers": [
                {
                    "host": "0.0.0.0",
                    "port": 3000,
                    "openRoamingCertificateId": 2,
                    "caCertificate": "-----BEGIN CERTIFICATE-----\nMIIEKjCCAxKgAwIBAgIRANb+lsED3eb4+6YKLFFYqEkwDQYJKoZIhvcNAQELBQAw\ngYcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMREwDwYDVQQHDAhT\nYW4gSm9zZTEcMBoGA1UECgwTQ2lzY28gU3lzdGVtcywgSW5jLjESMBAGA1UECwwJ\nRE5BU3BhY2VzMR4wHAYDVQQDDBVjaXNjby5vcGVucm9hbWluZy5vcmcwHhcNMjAx\nMTA1MjEzMzM1WhcNMjExMTA1MjIzMzM1WjCBpDEcMBoGCgmSJomT8ixkAQETDGRu\nYXNwYWNlczpVUzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMQ4wDAYDVQQKEwVD\naXNjbzEcMBoGA1UECxMTV0JBOldSSVggRW5kLUVudGl0eTE8MDoGA1UEAxMzNjQ3\nMDcwNDM4NDQ5NjQxMjAwMDAuMTg4MzQuaHMuY2lzY28ub3BlbnJvYW1pbmcub3Jn\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoqjP9QgRGyUO3p7SH9QK\nuTq6UYK7nAyjImgS4yQxeBkyZ5f2EUkX8m/AOcewpPxxPBhjPKRwxGeX3S50ksiA\nayFomUeslR0S0Z7RN9rzJa+CFyi9MwWIHMbLgXpB8tsSpgTAqwrzoTzOGq9fgC6u\npZhdZrBkg3FeJgD88goCi9mZDsY2YAoeGRLFJ2fR8iICqIVQy+Htq9pE22WBLpnS\nKjL3+mR9FArHNFtWlhKF2YHMUqyHHrnZnF/Ns7QNoMMF7/CK18iAKgnb+2wuGKM2\naEMddOeOTtz+i/rgjkp/RGMt011EdCsso0/cTo9qqX/bxOOCE4/Mne/ChMkQPnNU\nCwIDAQABo3IwcDAJBgNVHRMEAjAAMB8GA1UdIwQYMBaAFIG+4l5yiB01gP0sw4ML\nUSopqYcuMB0GA1UdDgQWBBSby1T9leYVOVVdOZXiHCSaDDEMiDAOBgNVHQ8BAf8E\nBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDQYJKoZIhvcNAQELBQADggEBAEyE\n1mjSUyY6uNp6W4l20w7SskALSJDRKkOeZxAgF3VMxlsCuEl70s9oEfntwIpyQtSa\njON/9yJHbwm/Az824bmk8Dc7AXIPhay+dftXb8j529gPuYB9AKoPNg0NctkyYCQh\na/3YQVdDWX7XgmEiXkL57M7G6+IdcPDONLArfjOcT9qHdkVVq1AIjlMSx3OQQmm/\nuoLb/G9q/97QA2/l8shG/Na8HjVqGLcl5TNZdbNhs2w9ogxr/GNzqdvym6RQ8vT/\nUR2n+uwH4n1MUxmHYYeyot5dnIV1IJ6hQ54JAncM9HvCLFk1WHz6RKshQUCuPBiJ\nwTw70BVktzJnb0VLeDg=\n-----END CERTIFICATE-----"
                }
            ],
            "radiusAccountingServers": [
                {
                    "host": "0.0.0.0",
                    "port": 3000,
                    "openRoamingCertificateId": 2,
                    "caCertificate": "-----BEGIN CERTIFICATE-----\nMIIEKjCCAxKgAwIBAgIRANb+lsED3eb4+6YKLFFYqEkwDQYJKoZIhvcNAQELBQAw\ngYcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMREwDwYDVQQHDAhT\nYW4gSm9zZTEcMBoGA1UECgwTQ2lzY28gU3lzdGVtcywgSW5jLjESMBAGA1UECwwJ\nRE5BU3BhY2VzMR4wHAYDVQQDDBVjaXNjby5vcGVucm9hbWluZy5vcmcwHhcNMjAx\nMTA1MjEzMzM1WhcNMjExMTA1MjIzMzM1WjCBpDEcMBoGCgmSJomT8ixkAQETDGRu\nYXNwYWNlczpVUzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMQ4wDAYDVQQKEwVD\naXNjbzEcMBoGA1UECxMTV0JBOldSSVggRW5kLUVudGl0eTE8MDoGA1UEAxMzNjQ3\nMDcwNDM4NDQ5NjQxMjAwMDAuMTg4MzQuaHMuY2lzY28ub3BlbnJvYW1pbmcub3Jn\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoqjP9QgRGyUO3p7SH9QK\nuTq6UYK7nAyjImgS4yQxeBkyZ5f2EUkX8m/AOcewpPxxPBhjPKRwxGeX3S50ksiA\nayFomUeslR0S0Z7RN9rzJa+CFyi9MwWIHMbLgXpB8tsSpgTAqwrzoTzOGq9fgC6u\npZhdZrBkg3FeJgD88goCi9mZDsY2YAoeGRLFJ2fR8iICqIVQy+Htq9pE22WBLpnS\nKjL3+mR9FArHNFtWlhKF2YHMUqyHHrnZnF/Ns7QNoMMF7/CK18iAKgnb+2wuGKM2\naEMddOeOTtz+i/rgjkp/RGMt011EdCsso0/cTo9qqX/bxOOCE4/Mne/ChMkQPnNU\nCwIDAQABo3IwcDAJBgNVHRMEAjAAMB8GA1UdIwQYMBaAFIG+4l5yiB01gP0sw4ML\nUSopqYcuMB0GA1UdDgQWBBSby1T9leYVOVVdOZXiHCSaDDEMiDAOBgNVHQ8BAf8E\nBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDQYJKoZIhvcNAQELBQADggEBAEyE\n1mjSUyY6uNp6W4l20w7SskALSJDRKkOeZxAgF3VMxlsCuEl70s9oEfntwIpyQtSa\njON/9yJHbwm/Az824bmk8Dc7AXIPhay+dftXb8j529gPuYB9AKoPNg0NctkyYCQh\na/3YQVdDWX7XgmEiXkL57M7G6+IdcPDONLArfjOcT9qHdkVVq1AIjlMSx3OQQmm/\nuoLb/G9q/97QA2/l8shG/Na8HjVqGLcl5TNZdbNhs2w9ogxr/GNzqdvym6RQ8vT/\nUR2n+uwH4n1MUxmHYYeyot5dnIV1IJ6hQ54JAncM9HvCLFk1WHz6RKshQUCuPBiJ\nwTw70BVktzJnb0VLeDg=\n-----END CERTIFICATE-----"
                }
            ],
            "radiusAccountingEnabled": false,
            "radiusEnabled": true,
            "radiusAttributeForGroupPolicies": "Filter-Id",
            "radiusFailoverPolicy": "Deny access",
            "radiusLoadBalancingPolicy": "Round robin",
            "ipAssignmentMode": "NAT mode",
            "adminSplashUrl": "http://example.com",
            "splashTimeout": "30 minutes",
            "walledGardenEnabled": true,
            "walledGardenRanges": [
                "example.com",
                "1.1.1.1/32"
            ],
            "minBitrate": 11,
            "bandSelection": "5 GHz band only",
            "perClientBandwidthLimitUp": 0,
            "perClientBandwidthLimitDown": 0,
            "visible": true,
            "availableOnAllAps": false,
            "availabilityTags": [ "tag1", "tag2" ],
            "perSsidBandwidthLimitUp": 0,
            "perSsidBandwidthLimitDown": 0,
            "mandatoryDhcpEnabled": false
        }
    ]
    ```
    """
    return dashboard.wireless.getNetworkWirelessSsids(network_id)


# @cache_json("cache/getNetworkWirelessSsidSplashSettings.json")
def get_network_wireless_ssid_splash_settings(
        dashboard: meraki.DashboardAPI,
        network_id: str,
        ssid_number: int
    ):
    """
    https://developer.cisco.com/meraki/api-v1/get-network-wireless-ssid-splash-settings/
    ```json
    {
        "ssidNumber": 0,
        "splashPage": "Click-through splash page",
        "useSplashUrl": true,
        "splashUrl": "https://www.custom_splash_url.com",
        "splashTimeout": 1440,
        "redirectUrl": "https://example.com",
        "useRedirectUrl": true,
        "welcomeMessage": "Welcome!",
        "themeId": "c3ddcb4f16785ee747ab5ffc10867d6c8ea704be",
        "splashLogo": {
            "md5": "abcd1234",
            "extension": "jpg"
        },
        "splashImage": {
            "md5": "542cccac8d7dedee0f185311d154d194",
            "extension": "jpg"
        },
        "splashPrepaidFront": {
            "md5": "542cccac8d7dedee0f185311d154d194",
            "extension": "jpg"
        },
        "guestSponsorship": {
            "durationInMinutes": 30,
            "guestCanRequestTimeframe": false
        },
        "blockAllTrafficBeforeSignOn": false,
        "controllerDisconnectionBehavior": "default",
        "allowSimultaneousLogins": false,
        "billing": {
            "freeAccess": {
                "enabled": true,
                "durationInMinutes": 120
            },
            "prepaidAccessFastLoginEnabled": true,
            "replyToEmailAddress": "user@email.com"
        },
        "sentryEnrollment": {
            "systemsManagerNetwork": { "id": "N_1234" },
            "strength": "focused",
            "enforcedSystems": [ "iOS" ]
        },
        "selfRegistration": {
            "enabled": true,
            "authorizationType": "admin"
        }
    }
    ```
    """
    return dashboard.wireless.getNetworkWirelessSsidSplashSettings(
        network_id,
        ssid_number
    )


def get_network_appliance_content_filtering(
        dashboard: meraki.DashboardAPI,
        network_id: str,
    ):
    """
    https://developer.cisco.com/meraki/api-v1/get-network-appliance-content-filtering/
    ```json
    {
        "allowedUrlPatterns": [
            "http://www.example.org",
            "http://help.com.au"
        ],
        "blockedUrlPatterns": [
            "http://www.example.com",
            "http://www.betting.com"
        ],
        "blockedUrlCategories": [
            {
                "id": "meraki:contentFiltering/category/1",
                "name": "Real Estate"
            },
            {
                "id": "meraki:contentFiltering/category/7",
                "name": "Shopping"
            }
        ],
        "urlCategoryListSize": "topSites"
    }
    ```
    """
    return dashboard.appliance.getNetworkApplianceContentFiltering(
        network_id
    )


# @cache_json("cache/getOrganizationApplianceSecurityEvents.json")
def get_organization_appliance_security_events(
        dashboard: meraki.DashboardAPI,
        org_id: str,
        **kwargs
    ):
    """
    https://developer.cisco.com/meraki/api-v1/get-organization-appliance-security-events/
    ```json
    [
        {
            "ts": "2018-02-11T00:00:00.090210Z",
            "eventType": "File Scanned",
            "clientName": "COMPUTER-M-V78J",
            "clientMac": "10:dd:b1:eb:88:f8",
            "clientIp": "192.168.128.2",
            "srcIp": "192.168.128.2",
            "destIp": "119.192.233.48",
            "protocol": "http",
            "uri": "http://www.favorite-icons.com/program/FavoriteIconsUninstall.exe",
            "canonicalName": "PUA.Win.Dropper.Kraddare::1201",
            "destinationPort": 80,
            "fileHash": "3ec1b9a95fe62aa25fc959643a0f227b76d253094681934daaf628d3574b3463",
            "fileType": "MS_EXE",
            "fileSizeBytes": 193688,
            "disposition": "Malicious",
            "action": "Blocked"
        },
        {
            "ts": "2018-02-11T00:00:00.090210Z",
            "eventType": "IDS Alert",
            "deviceMac": "00:18:0a:01:02:03",
            "clientMac": "A1:B2:C3:D4:E5:F6",
            "srcIp": "1.2.3.4:34195",
            "destIp": "10.20.30.40:80",
            "protocol": "tcp/ip",
            "priority": "2",
            "classification": "4",
            "blocked": true,
            "message": "SERVER-WEBAPP JBoss JMX console access attempt",
            "signature": "1:21516:9",
            "sigSource": "",
            "ruleId": "meraki:intrusion/snort/GID/1/SID/26267"
        }
    ]
    ```
    """
    return dashboard.appliance.getOrganizationApplianceSecurityEvents(
        org_id,
        total_pages='all',
        **kwargs
    )


@cache_json("cache/getNetworkEvents.json")
def get_network_events(
        dashboard: meraki.DashboardAPI,
        network_id: str,
        **kwargs
    ):
    """
    https://developer.cisco.com/meraki/api-v1/get-network-events/
    ```json
    {
        "message": "Some error",
        "pageStartAt": "2018-02-11T00:00:00.090210Z",
        "pageEndAt": "2018-02-11T00:00:00.090210Z",
        "events": [
            {
                "occurredAt": "2018-02-11T00:00:00.090210Z",
                "networkId": "N_24329156",
                "type": "association",
                "description": "802.11 association",
                "category": "80211",
                "clientId": "k74272e",
                "clientDescription": "Miles's phone",
                "clientMac": "22:33:44:55:66:77",
                "deviceSerial": "Q234-ABCD-5678",
                "deviceName": "My AP",
                "ssidNumber": 1,
                "eventData": {
                    "radio": "1",
                    "vap": "1",
                    "client_mac": "22:33:44:55:66:77",
                    "client_ip": "1.2.3.4",
                    "channel": "36",
                    "rssi": "12",
                    "aid": "2104009183"
                }
            }
        ]
    }
    ```
    """
    return dashboard.networks.getNetworkEvents(
        network_id,
        total_pages=3,
        perPage=1000,
        **kwargs
    )

@cache_json("cache/getNetworkEventsEventTypes.json")
@cache_csv("cache/getNetworkEventsEventTypes.csv")
def get_network_events_event_types(
        dashboard: meraki.DashboardAPI,
        network_id: str,
        **kwargs
    ):
    """
    https://developer.cisco.com/meraki/api-v1/get-network-events-event-types/
    ```json
    [
        {
            "category": "802.11",
            "type": "association",
            "description": "802.11 association"
        }
    ]
    ```
    """
    return dashboard.networks.getNetworkEventsEventTypes(
        network_id,
        **kwargs
    )

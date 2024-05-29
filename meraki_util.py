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
    response = requests.request('GET', url, headers=headers, data = payload)
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


# @cache_json("cache/getOrganizationDevices.json")
# @cache_csv("cache/getOrganizationDevices.csv")
def get_organization_devices(
    dashboard: meraki.DashboardAPI, organisation_id: str) -> dict:
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
    return dashboard.organizations.getOrganizationDevices(
        organisation_id,
        "all"
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
    dashboard: meraki.DashboardAPI, organisation_id: str):
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
        organisation_id
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


# @cache_json("cache/getDeviceSwitchPorts.json")
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

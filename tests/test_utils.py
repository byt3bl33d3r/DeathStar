import pytest
from deathstar.utils import posh_object_parser, posh_table_parser, beautify_json

posh_object_example = "Forest                     : bahbah.local\r\nCurrentTime                : 8/2/2020 4:20:36 AM\r\nHighestCommittedUsn        : 244872\r\nOSVersion                  : Windows Server 2016 Datacenter\r\nRoles                      : {SchemaRole, NamingRole, PdcRole, RidRole...}\r\nDomain                     : bahbah.local\r\nIPAddress                  : 10.0.0.46\r\nSiteName                   : Default-First-Site-Name\r\nSyncFromAllServersCallback : \r\nInboundConnections         : {11700df9-cada-43df-82f7-eccc4821d007}\r\nOutboundConnections        : {df05a9ea-801e-42ed-ad44-d80119189a95}\r\nName                       : DC2016.bahbah.local\r\nPartitions                 : {DC=bahbah,DC=local, CN=Configuration,DC=bahbah,DC=\r\n                             local, CN=Schema,CN=Configuration,DC=bahbah,DC=loca\r\n                             l, DC=DomainDnsZones,DC=bahbah,DC=local...}"
posh_table_example = "\r\nUserName         LogonDomain     AuthDomains     LogonServer     ComputerName   \r\n--------         -----------     -----------     -----------     ------------   \r\nblacksheep       BAHBAH                          DC2016          localhost      \r\nWIN7$            BAHBAH                                          localhost      \r\n\r\n\r\n\n\r\n\nGet-NetLoggedon completed!\r\n"


def test_posh_object_parse():
    parsed_output = posh_object_parser(posh_object_example)
    assert parsed_output == [
        {
            "currenttime": "8/2/2020 4:20:36 AM",
            "domain": "bahbah.local",
            "forest": "bahbah.local",
            "highestcommittedusn": "244872",
            "ipaddress": "10.0.0.46",
            "inboundconnections": "{11700df9-cada-43df-82f7-eccc4821d007}",
            "name": "DC2016.bahbah.local",
            "osversion": "Windows Server 2016 Datacenter",
            "outboundconnections": "{df05a9ea-801e-42ed-ad44-d80119189a95}",
            "partitions": "{DC=bahbah,DC=local, CN=Configuration,DC=bahbah,DC=local, CN=Schema,CN=Configuration,DC=bahbah,DC=local, DC=DomainDnsZones,DC=bahbah,DC=local...}",
            "roles": "{SchemaRole, NamingRole, PdcRole, RidRole...}",
            "sitename": "Default-First-Site-Name",
            "syncfromallserverscallback": "",
        }
    ]


def test_posh_table_parser():
    parsed_output = posh_table_parser(posh_table_example)
    assert parsed_output == [
        {
            "username": "blacksheep",
            "logondomain": "BAHBAH",
            "authdomains": "",
            "logonserver": "DC2016",
            "computername": "localhost",
        },
        {
            "username": "WIN7$",
            "logondomain": "BAHBAH",
            "authdomains": "",
            "logonserver": "",
            "computername": "localhost",
        },
    ]

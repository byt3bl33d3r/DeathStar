import pytest
from deathstar.utils import posh_object_parser, posh_table_parser, beautify_json

posh_object_example = 'Forest                     : bahbah.local\r\nCurrentTime                : 8/2/2020 4:20:36 AM\r\nHighestCommittedUsn        : 244872\r\nOSVersion                  : Windows Server 2016 Datacenter\r\nRoles                      : {SchemaRole, NamingRole, PdcRole, RidRole...}\r\nDomain                     : bahbah.local\r\nIPAddress                  : 10.0.0.46\r\nSiteName                   : Default-First-Site-Name\r\nSyncFromAllServersCallback : \r\nInboundConnections         : {11700df9-cada-43df-82f7-eccc4821d007}\r\nOutboundConnections        : {df05a9ea-801e-42ed-ad44-d80119189a95}\r\nName                       : DC2016.bahbah.local\r\nPartitions                 : {DC=bahbah,DC=local, CN=Configuration,DC=bahbah,DC=\r\n                             local, CN=Schema,CN=Configuration,DC=bahbah,DC=loca\r\n                             l, DC=DomainDnsZones,DC=bahbah,DC=local...}'
posh_table_example = '\r\nUserName         LogonDomain     AuthDomains     LogonServer     ComputerName   \r\n--------         -----------     -----------     -----------     ------------   \r\nblacksheep       BAHBAH                          DC2016          localhost      \r\nWIN7$            BAHBAH                                          localhost      \r\n\r\n\r\n\n\r\n\nGet-NetLoggedon completed!\r\n'

def test_posh_object_parse():
    parsed_output = posh_object_parser(posh_object_example)
    assert parsed_output == [
            {
                "CurrentTime": "8/2/2020 4:20:36 AM",
                "Domain": "bahbah.local",
                "Forest": "bahbah.local",
                "HighestCommittedUsn": "244872",
                "IPAddress": "10.0.0.46",
                "InboundConnections": "{11700df9-cada-43df-82f7-eccc4821d007}",
                "Name": "DC2016.bahbah.local",
                "OSVersion": "Windows Server 2016 Datacenter",
                "OutboundConnections": "{df05a9ea-801e-42ed-ad44-d80119189a95}",
                "Partitions": "{DC=bahbah,DC=local, CN=Configuration,DC=bahbah,DC=local, CN=Schema,CN=Configuration,DC=bahbah,DC=local, DC=DomainDnsZones,DC=bahbah,DC=local...}",
                "Roles": "{SchemaRole, NamingRole, PdcRole, RidRole...}",
                "SiteName": "Default-First-Site-Name",
                "SyncFromAllServersCallback": ""
            }
        ]

def test_posh_table_parser():
    parsed_output = posh_table_parser(posh_table_example)
    assert parsed_output == [
        {
            'UserName': 'blacksheep', 
            'LogonDomain': 'BAHBAH', 
            'AuthDomains': '',
            'LogonServer': 'DC2016',
            'ComputerName': 'localhost'
        },
        {
            'UserName': 'WIN7$',
            'LogonDomain': 'BAHBAH',
            'AuthDomains': '', 
            'LogonServer': '', 
            'ComputerName': 'localhost'
        }
    ]

PowerShell commands


## Install DNS and DHCP servers

Add-WindowsFeature Dhcp
Add-WindowsFeature RSAT -Dhcp
Add-DhcpServerInDC

Add-WindowsFeature Dns
Add-WindowsFeature RSAT -DNS -Server
Add-DnsServerPrimaryZona -Name <name> -ZoneFile <zonefile>
Add-DnsServerResourceRecordA -Name "www" -ZoneName <name>
IPv4Address <ip> 
Add-DnsServerResourceRecordA -Name "mail" -ZoneName <name>
IPv4Address <ip> 
Add-DhcpServer4Scope -Name "Houston Wired" -StartRange <ip> -EndRange <ip> -SubnetMask <mask> -Description <desc>
netsh dhcp server scope <network ip> set optionvalue 003 ipaddress <gateway ip>
netsh dhcp server scope <network ip> set optionvalue 006 ipaddress <dns server ip>
003	Router	Default gateway IP address
006	DNS Servers	IP addresses of DNS server
Add-DhcpServer4Failover -Name <name> -PartnerServer <domain> Lon-SVR1.Adatum.com -Scope <ip> 172.16.20.0, 172.16.22.0 -MaxClientLeadTime <time> ):15:00 -ServerRole Standby 

##Add conditional forwarders

Add-DnsServerConditionalFOrwarderZone -Name <name> -MasterServers <primary server ip>

## Install AD domai nservices

Install-WindowsFeature AD-Domain-Services
Import-Module ADDSDeployment
$password = ConvertTo-SecureString '<password' -AsPlainText -Force
Install-ADDSDomainController -DomainName <domain> Adatum.com -SafeModeAdministratorPassword $password -Force 

##Test connection

Test-NetConnection 172.16.0.1

##Trace route

Test-NetConnection -TraceRoute TOR-SVR1.adatum.com

##Get machine's IP Addresses - Loopback, IPv6, IPv4

Get-NetIPAddress

##Configure the new IP address 

New-NetIPAddress -InterfaceAlias "London_Network" -IPAddress 172.16.0.50 -PrefixLength 24

##Get the current IP configuration, default gateway etc.

Get-NetIpConfiguration

##Remove the wrong IP address 

Remove-NetIPAddress -InterfaceAlias "London_Network" -IPAddress 172.16.0.51 -PrefixLength 24 -DefaultGateway 172.16.0.2 -Confirm:$false

##Create new IP address with default gateway

New-NetIPAddress -InterfaceAlias "London_Network" -IPAddress 172.16.0.51 -PrefixLength 24 -DefaultGateway 172.16.0.1 -Confirm:$false

##Installing DHCP server

Open Server Manager > Add roles and features > Select Server Roles - DHCP and DNS server

Start DHCP Post-Install configuration wizard > Input authorisation and confirm

Tools > Services > Restart DHCP server service to refresh 

Server manager > DHCP > Select machine > IPv4 > Action > More Actions > New Scope > Input name for the scope > select IP range  and subnet mask > Add excluded addresses and delay for DHCP Offer > Lease Duration > Configure Default Gateway > More options > Activate the scope

##Configure Superscope 

Enter Name > Select scopes (hold CTRL) > Create

##Configure network connections through Windows GUI

Start > Network Connections > Open Ipv4 Properties > Set up IP 

##Configuring Ipv4 Failover - It synchronised DHCP leases accross servers. It also provides load balancing with requests. 

IPv4 > Select failover > Select scopes > Specify Failover Server > Add Server > Specify IP > Select mode and client lead time > Specify mode, shared secret 

##Create routing and remote address

Tools > Routing and remote access 

IPv4 > General > New Routig Protocol > DHCP Relay Agent > Open Properties > Put servers IP address > OK > Create new interface > Select interface to relay to 


##Configuring IPv6 

Server Manager > Tools > DHCP > IPv6 > Enter Scope > Add Excluded Addresses 

PowerShell

ipconfig /renew6 

##Restart DNS 

Tools > DNS > Right-click on server > All Tasks > Restart 

##Add new host

Forward Lookup > right-click group > New Host > Configure name, ip address 


##Set ISATAP Router. ISATAP is a method of transmitting IPv6 packets on an IPv4 network 

Set-NetIsatapConfiguration -Router 172.16.0.1

##Create ISATAP IPv6 Network 

New-NetRoute -InterfaceIndex 15 -DestinationPrefix fd00::/64 -Publish Yes

##Get ISATAP Interface Configuration 

Get-NetIPAddress -InterfaceIndex 15

##Configuring native IPv6 connection 

##Advertise address - create interface 

Set-NetIPInterface –AddressFamily ipv6 –InterfaceAlias “London_Network” –Advertising Enabled –AdvertiseDefaultRoute Enabled
 
##Setup route

New-NetRoute -InterfaceAlias “London_Network” -DestinationPrefix fd00::/64 -Publish Yes

##Ping a host using IPv6

Ping LON-DC1 -6

##Enable 6to4 translation 

Set-Net6to4Configuration -State Enabled

##Enable 6to4 Forwarding 

Set-NetIPInterface –InterfaceAlias “6to4_Adapter” –Forwarding Enabled

##Enable 6to4 connectivity 

Set-Net6to4Configuration –State Enabled

##Start new zone

Tools > DNS > Right-click Forward Lookup Zones > New Zone > Select zone type > type the zone name > create zone file setting > 


##Create new conditional forwarder 
## Conditional forwarders are DNS servers that only forward queries for a specific domain name.

Open DNS manager > Expand server > Right-click conditional forwarders > Type in domain and IP 

##Installing AD Domain Controller Active Directory

Install Active Directory Domain Services through Server Manager

After installation click Promote this server to a domain controller > Input Password > Select options

##Creating new alias 

Open DNS manager from Server Manager > Right Click member of FOrward Lookup Zones > Click New Alias (CNAME) 

##Refresh DNS

ipconfig /flushdns

##Installing DNS Server and configuring it through PowerShell

Import-Module DnsServer

Add-DnsServerClientSubnet -Name "UKSubnet" -IPv4Subnet "172.16.0.0/24"

Add-DnsServerClientSubnet -Name "CanadaSubnet" -IPv4Subnet "172.16.18.0/24"

Add-DnsServerZoneScope -ZoneName "Adatum.com" -Name "UKZoneScope"

Add-DnsServerZoneScope -ZoneName "Adatum.com" -Name "CanadaZoneScope"

Add-DnsServerResourceRecord -ZoneName "Adatum.com" -A -Name "www" -IPv4Address "172.16.0.41" -ZoneScope "UKZoneScope"

Add-DnsServerResourceRecord -ZoneName "Adatum.com" -A -Name "www" -IPv4Address "172.16.18.17" -ZoneScope "CanadaZoneScope"

Add-DnsServerQueryResolutionPolicy -Name "UKPolicy" -Action ALLOW -ClientSubnet "eq,UKSubnet" -ZoneScope "UKZoneScope,1" -ZoneName "Adatum.com"

Add-DnsServerQueryResolutionPolicy -Name "CanadaPolicy" -Action ALLOW -ClientSubnet "eq,CanadaSubnet" -ZoneScope "CanadaZoneScope,1" -ZoneName Adatum.com

##Get DNS server address

Get-DnsClientServerAddress

##Get DNS cache

Get-DnsClientCache

##Clear DNS Cache

Clear-DnsClientCache

##Location of hosts on Windows Machine

notepad C:\windows\system32\drivers\etc\hosts 

##Implementing IPAM - IP Address Management

Server Manager > Add roles and features > Add IP Address Management feature > Install

Click IPAM > Connect to server > Provision server > Enter name for provisioning method 

Configure Server Discovery > Get Forests > Reopen the window > Add forest

Start server discovery 

Select or add servers to manage 

Invoke IPAM Policies

Invoke-IpamGpoProvisioning –Domain Adatum.com -DomainController lon-dc1.adatum.com –GpoPrefixName IPAM –IpamServerFqdn LON-SVR2.adatum.com –DelegatedGpoUser Administrator


##Open Active Directory AD Centre

Server Manager > Tools > Active Directory Administrative Centre > Add, change goups

##To open Microsoft Management Console - it is used to manage certifications etc.

cmd > mmc

##Install Remote access through web application

Server Manager > Add features > Add Web Application Proxy 

##Disable anonymous authentication 

Server Manager > Internet Information Services Manager > Expand Sites > Click Website > Double click Authentication > Disable anonymous authentication 

##Get group polocy information

gpresult /R

##Get Direct Access Client settings 

Get-DAClientExperienceConfiguration

##Implementing VPN 

1.Add certificate for the user 
2. Open Internet Information Services Manager > Default Web Bindings > Default Website > Bindings > Add Site Binding > Change to https and add SSL created in the first step 
3.Routing and remote access > Disable remote access for the server > Configure remote access > Custom configuration > Select VPN access > Start
Open server properties > Security > Select SSL certificate created in step 1 > Select adapter in IPv4 or IPv6 
4. Network policy server > Create new policy for network policies > Name it and select VPN as access type > Add groups or user to use the VPN > Configure access, do not use MSCHAP v1 

##Validating VPN 

System > Advanced settings > Change groups if necessary 

Enable internet interface in Network Connections (Disable others) > Confirm IP settings in Network Connections 

##Configuring VPN 

Network and Sharing Centre > Set up new connection > Select connection option (workplace) > Use VPN > Configure Address and options > Finish
Network and Sharing Centre > Change adapter settings > Connect to VPN > Enter credentials > Connect

If necessary install certificate to a file from Certificate Authority in Server Manager from VPN creator > Right -click certificate and install on local computer > Store certifications in Trusted Root Certificates folder 

Open mmc > Add Certificate Snap-in for Computer > Verify it by checking it exist in Trusted Root Certificates folder

NetworkConnections > Right click VPN connections > Select Security options > configure type of VPN use configured authentication 

Open mmc > Add Group Policy Object 

Sign in to VPN after restart using Network sign-in

##Opening local group policy editor

Search gpedit.msc


##Create virtual machine entwork addapter 

Add-VMNetworkAdapter -VMName 20741B-LON-SVR1-B -Name "New Network Adapter"

##Connect the adapter to a device 

Connect-VMNetworkAdapter -VMName 20741B-LON-SVR1-B -Name “New Network Adapter” -SwitchName “External Switch

##Enable DHCP Guard on virtual machine

Open Hyper V manager > right click on machine > Settings > Network Adapter > Advanced features > Select required security features 

##Set virtual adapter to have dhcp guard on 
Set-VMNetworkAdapter -VMName 20741B-LON-DC1-B -DhcpGuard On












1.	Create a VM- Windows Server 2012 or 2016 

Install Hyper V on Windows 10 Pro. 
```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
```
Create virtual switch
```powershel
New-VMSwitch -name ExternalSwitch  -NetAdapterName Ethernet -AllowManagementOS $true
```

Create new VM in PowerShell ISE

```powershell 
$VMName = "VMNAME"

 $VM = @{
     Name = $VMName
     MemoryStartupBytes = 2147483648
     Generation = 2
     NewVHDPath = "C:\Virtual Machines\$VMName\$VMName.vhdx"
     NewVHDSizeBytes = 10,737,418,240
     BootDevice = "VHD"
     Path = "C:\Virtual Machines\$VMName"
     SwitchName = [string]"ExternalSwitch"
 }

 New-VM @VM
```
Add new images and change boot order for your new VMs in ISE

```powershell
Add-VMDvdDrive -VMName LAB-SVR -Path C:\WindowsServer2016.iso

$VmName = [string]"LAB-CLI"

$win10g2 = Get-VMFirmware $VmName

$hddrive = $win10g2.BootOrder[0]

$pxe = $win10g2.BootOrder[1]

$dvddrive = $win10g2.BootOrder[2]

Set-VMFirmware -VMName $VmName -BootOrder $dvddrive,$hddrive,$pxe
```

Start and connect to the machines 
```powershell
Start-VM -Name LAB-SVR
$s = New-PSSession -ComputerName LAB-SVR
Enter-PSSession -Session $s
```


3.	Configure IP address on Server	

```powershell

Get-Netadapter

$ipParams = @{
InterfaceIndex = 8
IPAddress = "192.168.20.10"
DefaultGateway =  "192.168.2.1"
PrefixLength = 24
AddressFamily = "IPv4"
}

New-NetIPAddress @ipParams

Set-DNSClientServerAddress –InterfaceIndex 8 –ServerAddresses 192.168.2.11,10.1.2.11
Set-NetIPInterface -InterfaceAlias Ethernet0 -Dhcp Enabled
```
- IP 192.168.20.10 
- Subnet mask 255.255.255.0 
- Gateway 192.168.20.1
- Pref DNS server 127.0.0.1 (later change it to 192.168.20.10)
 
3.	Install Active directory Domain services
Together with DNS, DHCP through Add roles and features 
 
 ```powershel
 Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
 Install-WindowsFeature DNS -IncludeManagementTools
 Install-WindowsFeature DHCP -IncludeManagementTools
 ```

4.	After the installation, Promote server to  Domain Controller 
```powershell
Install-Addsdomaincontroller 
```
a.	Add a new forest – kan.com

```powershell
Install-ADDSForest -DomainName "corp.contoso.com" -DatabasePath "d:\NTDS" -SysvolPath "d:\SYSVOL" -LogPath "e:\Logs" -DomainNetbiosName "name" 
```

b.	Select minimum functional level domain- Windows server 2012 R2
 
c.	NetBIOS name >automatically shows > kan

d.	Specify ADDS Log, Sysvol folder (you can leave it to the default C:\
 
 
You can see the script for the options you selected
e.	Install the prerequisite screen click next
h.	It will prompt you to restart automatically
i.	Login as domain/administrator (kan/administrator) with password
5.	 
6.	Post install DNS click next with the defaults and finalise ok

7.	Go to ADUC to create users 
 
a.	Expand your domain
b.	Right click users details area and create a new user
c.	Sachin Tendulkar , enter the password , remove the password change at next logon, 
8.	Configure AD DNS – go to DNS manager 

a.	Expand your domain
b.	Reverse look up zone>Create a  new pointer record the record should have the name 192.168.20.10  and record type as  pointer , data as dc-01.kan.com

c.	 
i.	Check the nslookup command to verify because when you install the dns it updates the dns server to 127.0.0.1 so check that and modify 198.168.20.10 
ii.	Go to network connection or type ncpa.cpl properties and change your preferred DNS server IP to 192.168.20.10 
iii.	(IP addresses to name)  – Create a zone 
d.	Type the network id  198.168.20.10
e.	Dc-01.Kan.com
9.	Back to DNS Manager
10.	Forward look up zone 
a.	At _msdc.kan.com -> double click and select name server>  edit
b.	Name server> double click> resolve  ok ( dc-01 ip address should display 192.168.20.10

c.	SOA record double click and edit > click resolve
d.	Last record > double click > under security > select every one > ok

11.	Check at command prompt
a.	Nslookup
i.	Should display 192. 168.20.10
ii.	Dc-01.kan.com
12.	Next post install DHCP config
a.	Expand DHCP -> IPV4
b.	Create a new scope under IPv4 
c.	Enter the Name for the scope : kan-DHCP
i.	Range 192.168.20.100 to 192.168.20.254
ii.	Start 
iii.	Select, Yes I want to configure this option now 
iv.	Router default gateway IP address – 192.168.20.1
v.	Servername –Dc-01 and 
vi.	enter domain name DNS server  192.168.20.10
vii.	click resolve ip 
viii.	Activate the scope

Go to client 
		Test from client
		Get IP from DHCP server>
  Go to network properties obtain ip address from dhcp 
		Go to the computer properties –Change it to join domain
						Kan.com 
						Enter the credentials 
							Userid / password of administrator

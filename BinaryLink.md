Internal Binary Exam Practice (project Session 4 A) 
1.	Create 2 VM  
a.	Windows server 2012 or 2016  
b.	Windows 10 machine

Create new VM in PowerShell ISE

Install Hyper V on Windows 10 Pro. 

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
```
Create virtual switch
```powershel
New-VMSwitch -name ExternalSwitch  -NetAdapterName Ethernet -AllowManagementOS $true
```
Can also use "Default Switch" if the communication is only itnernal 

```powershell 

$VMName = "VMNAME"

 $VM = @{
     Name = $VMName
     MemoryStartupBytes = 4GB
     Generation = 2
     NewVHDPath = "C:\Virtual Machines\$VMName\$VMName.vhdx"
     NewVHDSizeBytes = 60GB
     BootDevice = "VHD"
     Path = "C:\Virtual Machines\$VMName"
     SwitchName = "Default Switch"
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


2.	Configure Static IP address for server and client with your 
a.	Subnet mask , preferred DNS server 

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

Rename-Computer

```

3.	Install Active directory Domain services 
a.	Optionally you can install DNS and DHCP together while installing ADDS 
i.	If you install together with DNS and DHCP, You should perform post installation tasks, which is DHCP should have security groups should be created 
ii.	Also you must promote this server to a domain controller 
iii.	ADDS is closely coupled with DNS, it works with the help of DNS
iv.	During the installation it will install GPM
v.	RSAT and LDS tools 

 ```powershell
 Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
 Install-WindowsFeature DNS -IncludeManagementTools
 Install-WindowsFeature DHCP -IncludeManagementTools
 ```

4.	After the installation you must promote server to a DC 
a.	While promoting a DC you create a new forest with a root domain name 
b.	Example:- you domain name is yourname.com (ADF.com)
c.	Select minimum functional level domain to Windows server 2012
d.	Enter the NetBIOS name  for legacy clients 
e.	Leave the default Sysvol folder path 
f.	Optionally you can generate the PowerShell script and save it 
g.	Restart the server after you  promote it to a DC

After the installation, Promote server to  Domain Controller - Installing new Forest will automatically promote the machine to DC

```powershell
Install-ADDSForest -DomainName "corp.contoso.com" -DatabasePath "d:\NTDS" -SysvolPath "d:\SYSVOL" -LogPath "e:\Logs" -DomainNetbiosName "name" 
```

```powershell
Restart-Computer
```
5.	Create 3 users ( you can use PowerShell or server manager tool ADUC) 
a.	Make sure that you remove the password change at next logon and password never expires 

Create user using ISE 

```powershell
$password = ConvertTo-SecureString "passwd123" –AsPlainText –Force
$user = "userxyz"
New-ADUser -Name $user -AccountPassword $password
Set-ADUser $user -PasswordNeverExpires $false -ChangePasswordAtLogon:$false
```

Script to create users from CSV file 

```powershell
$csvfile = "C:\Path"
$OU= "ou=unit,dc=domain,dc=com" 

$users= Import-CSV $csvfile

Foreach($i in $users){
	$DisplayName = $i.FirstName + " " + $i.LastName
	$SecurePass = ConvertTo-SecureString $i.DefaultPassword -AsPlainText -Force
	New-Aduser -Name $i.FirstName -Given $i.FirstName -Surname $i.LastName -DisplayName $DisplayName -Department $i.Department -Path $OU -AccountPassword $SecurePass -Enabled $true
}

```
CSV file should have the following structure 

FirstName,LastName,Department,DefaultPassword
Name,LastName,Dept,Password 
Line 3
...

6.	Join the client (CL-01) computer to the Domain controller 
a.	Ping and text whether you can able to reach the DC or not from the client

```powershell
Add-Computer –DomainName "YourDomainName"  -Restart
```

7.	Configure DNS  with Forward look up zone and reverse look up zone for ADF.com
a.	Create necessary A record in forward lookup one and pointer record in reverse lookup zone
b.	From the client computer you should be able to resolve the IP address when the user type with the help of NSLOOKUP <ADF.com>

To create forwarding zone
To create A record 
To create reverse lookup pointer

```powershell
Add-DnsServerPrimaryZone -Name woshub.com -ReplicationScope "Forest" –PassThru
Add-DnsServerResourceRecordA -Name ber-rds1 -IPv4Address 192.168.100.33 -ZoneName woshub.com
Add-DnsServerResourceRecordPtr -Name "17" -ZoneName "0.168.192.in-addr.arpa" -AllowUpdateAny -TimeToLive 01:00:00 -AgeRecord -PtrDomainName "host17.contoso.com"
``
This command adds a type PTR DNS record in the zone named contoso.com. The record maps IP address 192.168.0.17 to the name host17.contoso.com. The command includes the AllowUpdateAny and AgeRecord parameters, and provides a TTL value. Because the command includes the AgeRecord parameter, a DNS server can scavenge this record.

To create reverse lookup
```powershell
Add-DnsServerPrimaryZone -NetworkID “192.168.20.0/24” -ReplicationScope “Domain” 
```

8.	Configure DHCP 
a.	Give a Range name 
i.	Reserve  3 IPS for special objects ( like printer and other devices) example 10,11,12
ii.	Exclude certain IP range (13 to 20)
iii.	Activate the scope 

```powershell
Add-DhcpServerV4Scope -Name "DHCP Scope" -StartRange 192.168.1.150 -EndRange 192.168.1.200 -SubnetMask 255.255.255.0
Set-DhcpServerV4OptionValue -DnsServer 192.168.1.10 -Router 192.168.1.1
Set-DhcpServerv4Scope -ScopeId 192.168.1.10 -LeaseDuration 1.00:00:00
Add-Dhcpserverv4ExclusionRange -ScopeId 10.1.1.0 -StartRange 10.1.1.1 -EndRange 10.1.1.10
Add-DhcpServerv4Reservation -ScopeId 10.10.10.0 -IPAddress 10.10.10.8  -Description "Reservation for Printer"
Restart-service dhcpserver
```

9.	From CL01 login with the help of user id you created at DC to verify the connectivity to the domain 
a.	IP address from DHCP
b.	Resolving DNS 
10.	Create 2 OU’s Navy , and Army add 2 users to army and add 1 user to navy
a.	Create a GPO to hide the Date and time from system tray and roll out to Army 

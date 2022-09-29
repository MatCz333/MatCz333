>>Install AD DS on LON-SVR1

>>At the command prompt in the Windows PowerShell command-line interface, type the >>following command, and then press Enter:

Install-WindowsFeature -Name AD-Domain-Services -ComputerName LON-SVR1

>>Install role for the Domain Services 

Install-ADDSDomainController  

>>Confirm AD DS is isntalled.

Get-WindowsFeature -ComputerName LON-SVR1

>>Add Servers 

Go to All Servers in Server Manager.

Right Click> Add Server> Find now > Add Server with installed AD DS > Promote to Domain Controller > Install using GUI or use PowerShell Script

Invoke-Command -ComputerName LON-SVR1 {Install-ADDSDomainController -NoGlobalCatalog:$true -Credential (Get-Credential) -CriticalReplicationOnly:$false -DatabasePath “C:\Windows\NTDS” -DomainName “Adatum.com” -InstallDns:$false -LogPath “C:\Windows\NTDS” -NoRebootonCompletion:$false -SiteName “Default-First-Site-Name” -SysvolPath “C:\Windows\SYSVOL” -Force:$true }

>>Go to Server Manager >> AD DS 

Best Practices Analyser > Start BPA Scan > See results

>>Cloning AD DC

Server Manager > Active Directory Adminsitrative Center > Domain Controllers > Select Server > Add to Clonable Domain Controller Group 

>> Open PowerShell

Get-ADDCCloningExcludedApplicationList -GenerateXML

>>Run the following command to create the DCCloneConfig.xml file:

New-ADDCCloneConfigFile

>> On host in hyper V manager right click on server and click export 

Start Virtual machine after export > in Hyper V manager import virtual machine > Select location where it was cloned > Select copy the virtual machine > Rename the new machine 

>>To reset user password

Go to Active Directory Adminsitrative Center > Overview > Reset Password > Enter user's credentials

>> To Search for users 

Go to Active Directory Adminsitrative Center > Overview > Global Search > Search 

>>To create new computer 

Go to Active Directory Adminsitrative Center > Double click on domain > Computers > New > Properties 

PowerShell script

New-ADComputer -Enabled:$true -Name:"LON-CL4" -Path:"CN=Computers,DC=Adatum,DC=com" -SamAccountName:"LON-CL4" -Server:"LON-DC1.Adatum.com"

>>Repair trust relationship 

Test-ComputerSecureChannel -Repair 

>>Create OU

Active Directory Users and Computers > Right-click domain > New OU > Enter name

>>Create Group 

Active Directory Users and Computers > Right-click OU > New Group > Enter name 

>>Create new Users

New-ADUser -Name Ty -DisplayName "Ty Carlson" -GivenName Ty -Surname Carlson -Path "ou=London,dc=adatum,dc=com"

>>Create user's password

Set-ADAccountPassword Ty

>>Enable User's password

Enable-ADAccount Ty

>>Create new Group 

New-ADGroup LondonBranchUsers -Path "ou=London,dc=adatum,dc=com" -GroupScope Global -GroupCategory Security

>>Add User to a Group

Add-ADGroupMember LondonBranchUsers -Members Ty

>>Display users for a Group

Get-ADGroupMember LondonBranchUsers


>>Script to create users from CSV file 

$csvfile = "C:\Path"
$OU= "ou=unit,dc=domain,dc=com" 

$users= Import-CSV $csvfile

Foreach($i in $users){
	$DisplayName = $i.FirstName + " " + $i.LastName
	$SecurePass = ConvertTo-SecureString $i.DefaultPassword -AsPlainText -Force
	New-Aduser -Name $i.FirstName -Given $i.FirstName -Surname $i.LastName -DisplayName $DisplayName -Department $i.Department -Path $OU -AccountPassword $SecurePass -Enabled $true
}

CSV file should have the following structure 

FirstName,LastName,Department,DefaultPassword
Name,LastName,Dept,Password 
Line 3
...


##Trust relationships 

Server Manager > Active Directory Domains and Trusts > Right-click domain > Trusts > New Trust > Forest or External Trust > After creation Right-click > Properties > Validate 

Server Manager > Active Directory Users and Computers > View > Advanced Features > Go to server you want to build trust and add group from another forest/domain > Allow to authenticate 

Can create new folders and share them by using advaned sharing and add group from another domain/forest that can acces it 

##Creating new child domains 

Install AD DS from add features in Server Manager >Promote to AD DC > Add to existing forest > Add Child domain > Enter new child domain > Install 

On new child domain enter service manager > Active directory Domains and Trusts > Right click domain > Properties > Validate incomind trust 

##Creating Group Policy 

Server Manager > Group Policy Management > Create Object > Edit > Create Policies
Right-click forest in Group Policy Management > Link to current GPO

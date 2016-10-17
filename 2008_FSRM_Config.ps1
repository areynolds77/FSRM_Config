#Get System info
$majorVer = [System.Environment]::OSVersion.Version.Major
$minorVer = [System.Environment]::OSVersion.Version.Minor
$date = Get-Date -Format dd-MM-yyyy

$cred = Get-Credential -Message "Enter the credentials that should be used to update Ransomware File Groups weekly."
#$domain = Read-Host "Enter your domain name"
$smtp_server = Read-Host "Enter the address of the smtp server you wish to use to send alert messages"
$admin_email = Read-Host "Enter the e-mail address you wish to receive notications at"
$from_email = Read-Host "Enter the e-mail address that messages should appear to originate from"


$FSRM_Log_Path = Read-Host "Enter the path you wish to store FSRM logs, reports, and scripts in (This will not overwrite your current settings if you allready have FSRM installed!)"

Write-Output "Checking if FSRM is installed...`r`n"
#Check if FSRM is allready installed
$Check_FSRM = (Get-WindowsFeature -Name FS-Resource-Manager).Installed
if ($Check_FSRM -ne "Installed") {
    #Server 2008R2
    Write-Output "FSRM not found...Installing (2008R2)"
    Add-WindowsFeature FS-FileServer, FS-Resource-Manager
    $OS = "2008R2"
}

#Create honeypot folders & files
$SMBShares = Get-WmiObject -class win32_share | Where-Object {$_.Name -ne "ADMIN$" -and $_.Name -ne "IPC$"} | Out-GridView -Title "Select Shares to create honeypot folders in:" -PassThru

$honeypots = @()
do {
    $MaxHoneypotSize = Read-Host "How large should each honeypot folder be? (i.e 10MB , 500MB , or 1GB -- Remember, the larger the folders the longer it will take for them to be encrypted!)"
} while ( $MaxHoneypotSize -notmatch "\d*KB|\d*MB|\d*GB" )

Write-Output "Creating honeypot folders..."
$FileSize = $MaxHoneypotSize / 1000 
$FileSize = [Math]::Round($FileSize, 0)

foreach ($Folder in $SMBShares) {
    #Set initial variables
    $progresscount = 1
    $honeypot_folder = $Folder.Path
    $honeypot_folder_a = "$honeypot_folder\___Honeypot"
    $honeypot_folder_z = "$honeypot_folder\zzz___Honeypot"
    $honeypots += $honeypot_folder_a 
    $honeypots += $honeypot_folder_z
    
    #Create honeypot folders
    New-Item $honeypot_folder_a -ItemType Directory | ForEach-Object {$_.Attributes = "hidden"} 
    New-Item $honeypot_folder_z -ItemType Directory | ForEach-Object {$_.Attributes = "hidden"}

    #Create honeypot files
    Write-Output "Creating honeypot files in $honeypot_folder_a" 
    1..100 | ForEach-Object { 
        fsutil.exe file createnew "$honeypot_folder_a\DO_NOT_OPEN_$_.txt" $FileSize
        Write-Progress -Activity "Creating honeypot files in $honeypot_folder_a..." -PercentComplete ($progresscount/$_.Count)
        $progresscount++
    } | Out-Null 
    $progresscount = 1
    Write-Output "Creating honeypot files in $honeypot_folder_z"
    1..100 | ForEach-Object { 
        fsutil.exe file createnew "$honeypot_folder_z\DO_NOT_OPEN_$_.txt" $FileSize
        Write-Progress -Activity "Creating honeypot files in $honeypot_folder_a..." -PercentComplete ($progresscount/$_.Count)
        $progresscount++
    } | Out-Null
}

Write-Output "Configuring FSRM Global Settings"
#Set FSRM Global Settings   
if ($Check_FSRM -ne "Installed") {
    $ScriptPath = "$FSRM_Log_Path\Scripts"
    $LogPath = "$FSRM_Log_Path\Logs"
    $TemplatePath = "$FSRM_Log_Path\Templates"
    $IncidentPath = "$FSRM_Log_Path\Reports\Incidents"
    $ScheduledPath = "$FSRM_Log_Path\Reports\Scheduled"
    $InteractivePath = "$FSRM_Log_Path\Reports\Interactive"
    New-Item -ItemType Directory -Path $ScriptPath , $LogPath , $TemplatePath , $IncidentPath , $ScheduledPath , $InteractivePath 
    filescrn.exe admin options /smtp:$smtp_server /from:$from_email /adminemails:$admin_email
} else {
    $ScriptPath = "$FSRM_Log_Path\Scripts"
    $LogPath = "$FSRM_Log_Path\Logs"
    New-Item -ItemType Directory -Path $ScriptPath , $LogPath
}

#Create FSRM File Groups & Templates
Write-Output "Downloading latest Ransomware extension list from Experiant.ca"
$FilePatterns = ((Invoke-WebRequest -Uri "https://fsrm.experiant.ca/api/v1/combined").content | ConvertFrom-Json | ForEach-Object {$_.filters})
$xmlpatterns = @()
Foreach ($Pattern in $FilePatterns) {
    $xmlpatterns += "<Pattern PatternValue = '$Pattern' ></Pattern>"
}

$RansomwareFileGroup_String = @"
<?xml version="1.0" ?>
<Root >
<Header DatabaseVersion = '2.0' ></Header>
<QuotaTemplates ></QuotaTemplates>
<DatascreenTemplates ></DatascreenTemplates>
<FileGroups >
<FileGroup Name = 'Ransomware%sFile%sGroup' Id = '{7cf53902-2a03-43c6-a847-5364eecb7471}' Description = '' >
<Members >$xmlpatterns</Members>
<NonMembers ></NonMembers>
</FileGroup>
</FileGroups>
</Root>
"@ | Out-File $ScriptPath\RansomwareFileGroups.xml

$Honeypot_FileGroup_String = @"
<?xml version="1.0" ?>
<Root >
<Header DatabaseVersion = '2.0' ></Header>
<QuotaTemplates ></QuotaTemplates>
<DatascreenTemplates ></DatascreenTemplates>
<FileGroups >
<FileGroup Name = 'Honeypot%sFiles' Id = '{9a9be161-11cd-4ba3-ada0-52b09d6b46b8}' Description = '' >
<Members >
<Pattern PatternValue = '*.*' ></Pattern>
</Members>
<NonMembers ></NonMembers>
</FileGroup>
</FileGroups>
</Root>
"@ | Out-File $ScriptPath\HoneypotFileGroups.xml

$HoneypotDetector_Template = @"
<?xml version="1.0" ?>
<Root >
<Header DatabaseVersion = '2.0' ></Header>
<QuotaTemplates ></QuotaTemplates>
<DatascreenTemplates >
<DatascreenTemplate Name = 'Honeypot%sDetector' Id = '{bdb6bb7b-0867-4d8f-a4e2-3c0b3c07b139}' Flags = '0' Description = '' >
<BlockedGroups >
<FileGroup FileGroupId = '{9a9be161-11cd-4ba3-ada0-52b09d6b46b8}' Name = 'Honeypot%sFiles' >
</FileGroup>
</BlockedGroups>
<FileGroupActions >
<Action Type="2" Id="{7d1b5d38-7bf6-451f-bedd-7e611585d99c}" MailFrom="$from_email" MailReplyTo="" MailTo="[Admin%sEmail];[Source%sIo%sOwner%sEmail]" MailCc="" MailBcc="" MailSubject="Honeypot%sfile%stouched%sby%s[Source%sIo%sOwner]" MessageText="User%s[Source%sIo%sOwner]%sattempted%sto%smodify%s[Source%sFile%sPath]%sto%s[File%sScreen%sPath]%son%sthe%s[Server]%sserver.%sThis%sfile%sis%sin%sthe%s[Violated%sFile%sGroup]%sfile%sgroup,%sand%smay%spossibly%sindicate%sa%sransomware%sinfection.%sYour%saccount%shas%sbeen%sblocked%sfrom%saccessing%sthe%sfile%sserver.%sPlease%sturn%soff%syour%scomputer%simmediately,%sand%swait%sto%sbe%scontacted%sby%sEngineering." />
<Action Type="1" Id="{70aa711a-02d1-4bd6-a5fa-f4945c7dc7b9}" EventType="2" MessageText="User%s[Source%sIo%sOwner]%sattempted%sto%smodify%s[Source%sFile%sPath]%sto%s[File%sScreen%sPath]%son%sthe%s[Server]%sserver.%sThis%sfile%sis%sin%sthe%s[Violated%sFile%sGroup]%sfile%sgroup,%sand%smay%spossibly%sindicate%sa%sransomware%sinfection.%sYour%saccount%shas%sbeen%sblocked%sfrom%saccessing%sthe%sfile%sserver.%sPlease%sturn%soff%syour%scomputer%simmediately,%sand%swait%sto%sbe%scontacted%sby%sEngineering." />
<Action Type="3" Id="{4fb6378a-db20-4640-bda1-8f2d7d86e628}" ExecutablePath="C:\Windows\System32\cmd.exe" Arguments="/c%snet%sstop%slanmanserver%s/y" WorkingDirectory="C:\Windows\System32\" Account="3" MonitorCommand="0" KillTimeOut="0" LogResult="1" CurrentSid="S-1-5-21-187423309-3256056377-3149430587-500" />
</FileGroupActions>
</DatascreenTemplate>
</DatascreenTemplates>
<FileGroups 
></FileGroups>
</Root>
"@ | Out-File $ScriptPath\HoneypotScreen_Template.xml

$RansomwareDetector_Template = @"
<?xml version="1.0" ?>
<Root >
<Header DatabaseVersion = '2.0' ></Header>
<QuotaTemplates ></QuotaTemplates>
<DatascreenTemplates >
<DatascreenTemplate Name = 'Ransomware%sDetector' Id = '{17a1cdd8-aefd-461a-9fdb-2d19498a3098}' Flags = '0' Description = '' >
<BlockedGroups >
<FileGroup FileGroupId = '{7cf53902-2a03-43c6-a847-5364eecb7471}' Name = 'Ransomware%sFile%sGroup' >
</FileGroup></BlockedGroups><FileGroupActions >
<Action Type="2" Id="{11b50303-6f11-4d54-b4ba-de7bed9bda3b}" MailFrom="$from_email" MailReplyTo="" MailTo="[Admin%sEmail];[Source%sIo%sOwner%sEmail]" MailCc="" MailBcc="" MailSubject="Possible%sRansomware%sInfection%sDetected!" MessageText="User%s[Source%sIo%sOwner]%sattempted%sto%ssave%s[Source%sFile%sPath]%sto%s[File%sScreen%sPath]%son%sthe%s[Server]%sserver.%sThis%sfile%sis%sin%sthe%s[Violated%sFile%sGroup]%sfile%sgroup,%sand%smay%spossibly%sindicate%sa%sransomware%sinfection.%sPlease%sturn%soff%syour%scomputer%simmediately%sand%swait%sto%sbe%scontacted%sby%sengineering." />
<Action Type="1" Id="{684bc5ae-d376-42b4-be08-d219f3ad7920}" EventType="2" MessageText="User%s[Source%sIo%sOwner]%sattempted%sto%ssave%s[Source%sFile%sPath]%sto%s[File%sScreen%sPath]%son%sthe%s[Server]%sserver.%sThis%sfile%sis%sin%sthe%s[Violated%sFile%sGroup]%sfile%sgroup,%sand%smay%spossibly%sindicate%sa%sransomware%sinfection.%sPlease%sturn%soff%syour%scomputer%simmediately%sand%swait%sto%sbe%scontacted%sby%sengineering." />
</FileGroupActions>
</DatascreenTemplate>
</DatascreenTemplates>
<FileGroups >
</FileGroups>
</Root>
"@ | Out-File $ScriptPath\RansomwareScreen_Template.xml

filescrn.exe filegroup import /file:"$ScriptPath\HoneypotFileGroups.xml"
filescrn.exe filegroup import /file:"$ScriptPath\RansomwareFileGroups.xml"
filescrn.exe template import /file:"$ScriptPath\HoneypotScreen_Template.xml"
filescrn.exe template import /file:"$ScriptPath\RansomwareScreen_Template.xml"

Write-Output "Creating FSRM File Screens"
foreach ($honeypot in $honeypots) {
    filescrn.exe screen add /path:"$honeypot" /sourcetemplate:"Honeypot Detector"
}
$LocalDrives = Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.DriveType -eq '3'} | Select-Object DeviceId
foreach ($drive in $LocalDrives) {
    $drive = $drive.DeviceId
    filescrn.exe screen add /path:"$drive" /sourcetemplate:"Ransomware Detector" 
}

#Create Ransomware File Group Updater Script
$Update_Script = @"
`$smtp_server = '$smtp_server' 
`$from_email = '$from_email'
`$admin_email = '$admin_email'
`$FSRM_Log_Path = '$LogPath'
`$date = Get-Date -Format dd-MM-yyyy
`$newFilePatterns = ((Invoke-WebRequest -Uri "https://fsrm.experiant.ca/api/v1/combined").content | ConvertFrom-Json | ForEach-Object {`$_.filters}) 
`$newxmlpatterns = @()
Foreach (`$newPattern in `$newFilePatterns) {
    `$newxmlpatterns += "<Pattern PatternValue = '`$newPattern' ></Pattern>"
}

`$RansomwareFileGroup_String = @"
<?xml version="1.0" ?>
<Root >
<Header DatabaseVersion = '2.0' ></Header>
<QuotaTemplates ></QuotaTemplates>
<DatascreenTemplates ></DatascreenTemplates>
<FileGroups >
<FileGroup Name = 'Ransomware%sFile%sGroup' Id = '{7cf53902-2a03-43c6-a847-5364eecb7471}' Description = '' >
<Members >`$newxmlpatterns</Members>
<NonMembers ></NonMembers>
</FileGroup>
</FileGroups>
</Root>
`"@ | Out-File `$ScriptPath\RansomwareFileGroups.xml
filescrn.exe filegroup delete /filegroup:"Ransomware File Group" /quiet
filescrn.exe filegroup import /file:"`$ScriptPath\RansomwareFileGroups.xml"
`Send-MailMessage -From `$from_email -To `$admin_email -Subject "Ransomware File Group Updated" -SmtpServer `$smtp_server


"@
$Update_Script | Out-File -FilePath "$ScriptPath\Ransomware_File_Group_Update.ps1" 
$trigger = New-JobTrigger -Weekly -DaysOfWeek Tuesday -At 9:00AM
$options = New-ScheduledJobOption -RunElevated
Register-ScheduledJob -Trigger $trigger -ScheduledJobOption $options -Name "Ransomware File Group Updater" -FilePath "$ScriptPath\Ransomware_File_Group_Update.ps1" 
#Get System info
$majorVer = [System.Environment]::OSVersion.Version.Major
$minorVer = [System.Environment]::OSVersion.Version.Minor
$date = Get-Date -Format dd-MM-yyyy

$cred = Get-Credential -Message "Enter the credentials that should be used to update Ransomware File Groups weekly."
$domain = Read-Host "Enter your domain name"
$smtp_server = Read-Host "Enter the address of the smtp server you wish to use to send alert messages"
$admin_email = Read-Host "Enter the e-mail address you wish to receive notications at"
$from_email = Read-Host "Enter the e-mail address that messages should appear to originate from"


$FSRM_Log_Path = Read-Host "Enter the path you wish to store FSRM logs, reports, and scripts in (This will not overwrite your current settings if you allready have FSRM installed!)"

Write-Output "Checking if FSRM is installed...`r`n"
#Check if FSRM is allready installed
if ($majorVer -ge 6) {
        if ($minorVer -ge 2) {
            $Check_FSRM = (Get-WindowsFeature -Name FS-Resource-Manager).InstallState
            if ($Check_FSRM -ne "Installed") {
                #Server 2012
                Write-Output "FSRM not found...Installing (2012)"
                Install-WindowsFeature -Name FS-Resource-Manager -IncludeManagementTools
                #Remove Default File Screens
                Get-FSRMFileScreen | ForEach-Object {Remove-FSRMFileScreen -path $_.Path -confirm:$false}
                $OS = "2012" 
            }
        } elseif ($minorVer -ge 1) {
            $Check_FSRM = (Get-WindowsFeature -Name FS-Resource-Manager).Installed
            if ($Check_FSRM -eq "False") {
                #Server 2008R2
                Write-Output "FSRM not found...Installing (2008R2)"
                Add-WindowsFeature FS-FileServer, FS-Resource-Manager
                $OS = "2008R2"
            }
    } else {
        Write-Output "Unsupported Windows version detected. Quitting..."
        return
    }
}


#Create honeypot folders & files
if ($OS -eq "2012") {
    $SMBShares = Get-SmbShare -Special $false | Out-GridView -Title "Select Shares to create honeypot folders in:" -PassThru
} elseif ( $OS -eq "2008R2") {
    $SMBShares = Get-WmiObject -class win32_share | Where-Object {$_.Name -ne "ADMIN$" -and "IPC$"} | Out-GridView -Title "Select Shares to create honeypot folders in:" -PassThru
}

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
    if ($OS -eq "2012") {
        Set-FSRMSetting -SmtpServer $smtp_server -AdminEmailAddress $admin_email -FromEmailAddress $from_email 
        Set-FSRMSetting -ReportLocationIncident $IncidentPath -ReportLocationScheduled $ScheduledPath -ReportLocationOnDemand $InteractivePath
        Set-FSRMSetting -EmailNotificationLimit 10 -EventNotificationLimit 1
    } else {
        filescrn.exe admin options /smtp:$smtp_server /from:$from_email /adminemails:$admin_email
    }
     
} else {
    $ScriptPath = "$FSRM_Log_Path\Scripts"
    $LogPath = "$FSRM_Log_Path\Logs"
    New-Item -ItemType Directory -Path $ScriptPath , $LogPath
}

#Create honeypot FSRM Group
Write-Output "Creating FSRM File Groups"
if ($OS -eq "2012") {
    New-FSRMFileGroup -Name "Honeypot Files" -IncludePattern "*.*"

    #Create initial FSRM Cryptolocker Detection Group
    Write-Output "Downloading latest Ransomware extension list from Experiant.ca"
    $FilePatterns = ((Invoke-WebRequest -Uri "https://fsrm.experiant.ca/api/v1/combined").content | ConvertFrom-Json | ForEach-Object {$_.filters}) 
    New-FSRMFileGroup -Name "Ransomware File Groups" -IncludePattern $FilePatterns
    $FilePatterns | Out-File -FilePath $LogPath\Ransomware_File_Groups__$date.txt
    #Create FSRM Notification Actions
    $DetectionSubject = "Possible Ransomware Infection Detected! "
    $DetectionMessage = "User [Source Io Owner] attempted to save [Source File Path] to [File Screen Path] on server [Server].
    This file is in the [Violated File Group], and may possibly indicate a Ransomware infection. Please turn off your computer immediately,
    and wait to be contacted by Engineering."
    $HoneypotSubject = "Honeypot file touched by [Source Io Owner]"
    $HoneypotMessage = "User [Source Io Owner] attempted to modify [Source File Path] to [File Screen Path] on server [Server].
    This file is in the [Violated File Group] group, and may possibly indicate a Ransomware infection. Your account has been blocked from accessing the server.
    Please turn off your computer immediately, and wait to be contacted by Engineering."

    $Detection_Email_Notification = New-FSRMAction Email -MailTo "[Admin Email];[Source File Owner Email]" -Subject $DetectionSubject -Body $DetectionMessage -RunLimitInterval 10
    $Honeypot_Email_Notification = New-FSRMAction Email -MailTo "[Admin Email];[Source File Owner Email]" -Subject $HoneypotSubject -Body $HoneypotMessage -RunLimitInterval 10

    $Detection_Event_Notification = New-FSRMAction Event -EventType Warning -Body $DetectionMessage -RunLimitInterval 1
    $Honeypot_Event_Notification = New-FSRMAction Event -EventType Warning -Body $HoneypotMessage -RunLimitInterval 1

    New-FSRMFileScreenTemplate "Ransomware Detector" -IncludeGroup "Ransomware File Groups" -Notification $Detection_Email_Notification,$Detection_Event_Notification -Active:$false
    New-FSRMFileScreenTemplate "Honeypot Detector" -IncludeGroup "Honeypot Files" -Notification $Honeypot_Email_Notification,$Honeypot_Event_Notification -Active:$false

    Write-Output "Creating FSRM File Screens"
    foreach ($honeypot in $honeypots) {
        New-FSRMFileScreen -Path $honeypot -Template "Honeypot Detector" | Out-Null
    }
    $LocalDrives = (Get-Volume | Where-Object {$_.DriveType -eq 'Fixed' -and $_.DriveLetter -match "[A-Z]"}).DriveLetter
    foreach ($drive in $LocalDrives) {
        New-FSRMFileScreen -Path "$drive`:\" -Template "Ransomware Detector" 
    }
} 
    

#Create Ransomware File Group Updater Script
$Update_Script = @"
`$smtp_server = '$smtp_server' 
`$from_email = '$from_email'
`$admin_email = '$admin_email'
`$FSRM_Log_Path = '$LogPath'
`$date = Get-Date -Format dd-MM-yyyy
`$FilePatterns = ((Invoke-WebRequest -Uri "https://fsrm.experiant.ca/api/v1/combined").content | ConvertFrom-Json | ForEach-Object {`$_.filters}) 
`$OldFilePatterns = (Get-FSRMFileGroup -Name "Ransomware File Groups" ).IncludePattern
`$Compare = Compare-Object -ReferenceObject `$OldFilePatterns -DifferenceObject `$FilePatterns
if (`$Compare -eq `$null) {
    `$body = "No new ransomware file extensions added this week."
} else {
    `$body = `$Compare | Out-String
}
`$Compare| Out-File -filepath `$FSRM_Log_Path\Ransomware_File_Groups_Updated_`$date.txt

`Send-MailMessage -Body `$body -From `$from_email -To `$admin_email -Subject "Ransomware File Group Updated" -SmtpServer `$smtp_server
`Set-FSRMFileGroup -Name "Ransomware File Groups" -IncludePattern `$FilePatterns

"@
$Update_Script | Out-File -FilePath "$ScriptPath\Ransomware_File_Group_Update.ps1" 

#Create Scheduled Task to Update Ransomware File Groups
Write-Output "Creating Ransomware File Group Updater task"
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-file .\Ransomware_File_Group_Update.ps1" -WorkingDirectory "$ScriptPath"
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Tuesday -At 9:00AM 

$username = $cred.UserName
$Password = $cred.GetNetworkCredential().Password
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "Ransomware File Group Updater" -Description "Updates Ransomware File Groups from Experiant.ca" -RunLevel Highest -User $username -Password $password

#Create SMB Blocker task
$SMBBlock_Script = @"
`$domain = '$domain'
`$FSRM_Group_Name = "Honeypot Files"
`$smtp_server = '$smtp_server'
`$from_email = '$from_email'
`$admin_email = '$admin_email'
`$winlog = Get-WinEvent -MaxEvents 1 -FilterHashtable @{LogName="Application";ID=8215} | Where-Object {`$_.Message -match `$FSRM_Group_Name}
`$user = `$winlog.Message -match "`$domain\\\S*"
if (`$user -eq `$false) { break }
`$user = `$matches[0]
`$out = Get-SMBShare -special `$false | ForEach-Object { Block-SMBShareAccess -Name `$_.Name -AccountName `$user -force} | Out-String
Send-MailMessage -Body `$out -SmtpServer `$smtp_server -From `$from_email -To `$admin_email -Subject "SMB Access blocked for `$user"   
"@
$SMBBlock_Script | Out-File "$ScriptPath\SMB_Blocker.ps1"


$SMBBlock_Task = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2016-09-20T22:53:19.3711929</Date>
    <Author>Al Reynolds</Author>
  </RegistrationInfo>
  <Triggers>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="Application"&gt;&lt;Select Path="Application"&gt;*[System[Provider[@Name='SRMSVC'] and EventID=8215]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
    </EventTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$username</UserId>
      <LogonType>Password</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>
    <UseUnifiedSchedulingEngine>false</UseUnifiedSchedulingEngine>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-file ".\SMB_Blocker.ps1"</Arguments>
      <WorkingDirectory>$ScriptPath</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@

Register-ScheduledTask -Xml $SMBBlock_Task -User $username -Password $Password -TaskName "SMB Access Blocker" 

Write-Output "All Done! Make sure to double check and test. :)" 
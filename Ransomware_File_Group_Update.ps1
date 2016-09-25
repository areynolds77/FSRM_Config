$smtp_server = ""
$from_email = ""
$admin_email = ""
$FSRM_Log_Path = ""
$date = Get-Date -Format dd-MM-yyyy
$FilePatterns = ((Invoke-WebRequest -Uri "https://fsrm.experiant.ca/api/v1/combined").content | ConvertFrom-Json | ForEach-Object {$_.filters}) | Out-File -FilePath $LogPath\Ransomware_File_Groups__$date.txt
$OldFilePatterns = (Get-FSRMFileGroup -Name "Ransomware File Groups" ).IncludePatterns | Out-File 
$Compare = Compare-Object -ReferenceObject $OldFilePatterns -DifferenceObject $FilePatterns | Out-String -filepath $FSRM_Log_Path\Ransomware_File_Groups_$date.txt

Send-MailMessage -Body $Compare -From $from_email -To $admin_email -Subject "Ransomware File Group Updated" -SmtpServer $smtp_server
Set-FSRMFileGroup -Name "Ransomware File Groups" -IncludePattern $FilePatterns

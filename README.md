# FSRM_Config

This script (FSRM_Config.ps1) will install File Server Resource Manager (FSRM) and configure it to watch for ransomware infections. After installation you can also configure your file server to block infected users from accessing the server. 
If you already have FSRM installed, this will simply add the neccessary file groups/screens, as well as a weekly task to update the ransomware extension list. 

##System Requirements
* Windows Server 2008R2 or later
* Powershell 3.0 

##Installation Instructions
###For Server 2012 and up
1. [Download 'FSRM_Config.ps1'](https://github.com/areynolds77/FSRM_Config/blob/master/FSRM_Config.ps1)  
2. Run 'FSRM_Config.ps1' as an administrator.
    --Remember that you may need to adjust your execution policy to allow the running of unsigned scripts.
3. Follow the prompts.
4. Test!

###For Server 2008R2
1. [Download '2008_FSRM_Config.ps1'](https://github.com/areynolds77/FSRM_Config/blob/master/2008_FSRM_Config.ps1)
2. Run '2008_FSRM_Config.ps1' as an administrator.
    --Remember that you may need to adjust your execution policy to allow the running of unsigned scripts.
3. Follow the prompts.
4. Test!

##How it works 
FSRM provides two different avenues to protecting against ransomware infections: bait, and detection. 
###Bait (2012 Version)
Most ransomware infections will attempt to encrypt any file they have access to, regardless of whether that file is stored locally, or on a network share (even hidden shares are vulnerable).
This script will retreive a list of all the folders that are shared from the server, create a pair of hidden honeypot folders filled with fake files, and then configure FSRM to monitor these folders for any activity. 
By keeping the folders hidden, users will not see them, but ransomware infections will--and as soon as they attempt to modify any of the files within a honeypot folder, FSRM will send an e-mail and log an event to the Windows Event log. 
A scheduled task watches for these events, and will then block SMB access for the infected user.

* Why are two honeypot folders created? 
    Most ransomware infections start encrypting files in alphabetical order, which is why the first folder created is "___Honeypot". However, some infections work in reverse order, hence the second folder, "zzz___Honeypot". 
    This ***should*** ensure that your honeypot folders are encrypted before an actual data.
* Why are so many files created in each honeypot folder? 
    Because it takes time for FSRM to recognize that a ransomware infection is taking place and then lock the offending users out. The more files (and the larger the files) that the ransomware has to infect, the longer it will take before it starts infecting actual files.
* What happens when a honeypot file is modified? 
    FSRM will log an event to the Windows Event log indicating that a honeypot file has been modified. Task Scheduler watches for these events, and anytime one is logged will execute a script to block access to the file server.
* What do I do when I want to restore access for a blocked user? 
    Simply execute this command in an elevated Powershell console: 

    ```powershell
    Get-SMBShare -special $false | foreach { UnBlock-SMBShareAccess -Name $_.Name -AccountName $ACCOUNTNAME -force}
    ```

    *Where $ACCOUNTNAME is the SAM account name for the user you wish to restore access for.*
###Bait (2008 Version)
Server 2008R2 is unable to block SMB access for specific users, so instead, anytime a Honeypot file is modified, FSRM will kill the LANMAN server--which will kill everyone's access to the file server.

###Detection
[Experiant](http://experiant.ca/) is a Canadian IT firm that maintains a publicly accessible list of known ransomware extensions. FSRM can be configured to watch for these extensions, and alert admins & users if a matching file is detected. 
This script will check the Experiant list every Tuesday at 9AM for new patterns, and update the FSRM file groups if neccessary. It will also e-mail you a list of any new (or removed) patterns.
You can read more about their efforts to combat ransomware [here](https://fsrm.experiant.ca/) 

    * Why don't you block file server access when a file is detected matching the Experiant list? 

        Because the Experiant list can be somewhat generous in the extensions it detects--I tend to get a lot of false positives from it. You can if you want to though!

##To-Do
* Improve documentation
* Add error handling & input validation

##What it does
* Collects initial setup information:
    * User Credentials are used to create a scheduled task that downloads a list of  the latest ransomware extensions, and then update the FSRM File group.
    * STMP information is used to configure e-mail alerting. Anytime a file with a possible ransomware extension is detected, FSRM will e-mail both an admin, and the user that created the file. 
* Checks if FSRM is already installed
     * If FSRM is not installed, it will be installed, and the default file screens will be removed.
     * If FSRM is installed, only the Scripts and Log folders will be created.
* Create honeypot folders
    * Retreive a list of every SMB share on the local server (excluding the built-in windows shares)
    * Allow the user to select which shares should have honeypot folders
    * The user will be prompted to set a size for each honeypot folder--remember the larger the size of the folder, the longer it will take the ransomware to get to files that actually matter.
* Create File groups
    * Two File groups will be created; "Honeypot Files" and "Ransomware File Group"
        * Honeypot Files is simply an all files filter--using the default "All Files" group *could* cause the SMB Access Blocker script to run anytime a file screen using the "All Files" group is tripped.
        * The "Ransomware File Group" contains all of the extensions downloaded from Experiant's api. 
* Create File Screen Templates
    * Two File Screen Templates will be created; "Honeypot Detector", and "Ransomware Detector" 
        * The "Honeypot Detector" template uses the "Honeypot Files" file group, and will send an e-mail and log a message to the event log.
        * The "Ransomware Detector" template uses the "Ransomware File Group" and will send an e-mail and log a message to the event log.
        * Both templates notify both the FSRM Admin & the user who attempted to modify the file. 
* Create File screens
    * The script will then create a file screen using the "Honeypot Detector" File Screen Template for each of the shared folders the user selected earlier.
    * The script will then create a file screen using the "Ransomware Detector" File Screen Template for each of the local drives.
* Create Ransomware File Group Update Scripts
    * The script will create a powershell script (to be stored in the 'FSRM\Scripts' directory), that downloads the latest ransomware definitions from Experiant, updates the file group within FSRM, and then sends an e-mail to the FSRM admin listing any changes to the File Group.
    * The script will then create a scheduled task to execute the above task every Tuesday at 9:00AM.
* Create SMB Access Blocker script and task
    * The script will create a powershell script (to be stored in the 'FSRM\Scripts' directory) that will search the 'Application' Event Log for messages with an EventID of '8215'. 
    These are the events that FSRM logs anytime a File Screen is matched. The script will check to make sure that file screen matches the 'Honeypot Files' file group, so as to avoid accidental blocks.
    The script will then get a list of all SMB Shares on the local server, and block the offending user from accessing them. A notification message will be sent to the FSRM admin.
    * A Scheduled Task will then be created to executed the 'SMB Access Blocker' script anytime a message with an EventID of '8215' is logged.

##Security Risks
* The Powershell cmdlets for interfacing with Task Scheduler do not accept PSCredentials. This means that the provided password must be decrypted, and passed to Task Scheduler in plaintext. Make sure you close the Powershell console once the script has finished.




        


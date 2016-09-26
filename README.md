# FSRM_Config

This script (FSRM_Config.ps1) will install File Server Resource Manager (FSRM) and configure it to watch for ransomware infections. After installation you can also configure your file server to block infected users from accessing the server. 
If you already have FSRM installed, this will simply add the neccessary file groups/screens, as well as a weekly task to update the ransomware extension list. 

##Installation Instructions
1. [Download 'FSRM_Config.ps1'](https://github.com/areynolds77/FSRM_Config/blob/master/FSRM_Config.ps1)  
2. Run 'FSRM_Config.ps1' as an administrator.
    --Remember that you may need to adjust your execution policy to allow the running of unsigned scripts
3. Follow the prompts.
4. Once the script has finished, if you want to block any user that modifies one of the honeypot files, you will need to manually create a new scheduled task:
    + Open "Task Scheduler"
    + Create a new Task
    + Check the following boxes on the "General" tab:
        + "Run whether user is logged on or not"
        + "Run with highest priveleges"
    + Create a new "Trigger"
        + Begin the task "On an event"
        + Set the "Log" to "Application"
        + Set the "Source" to "SRMSVC"
        + Set the "Event ID" to "8215"
    + Create a new "Action"
        + Set the "Program/Script" field to "powershell.exe"
        + Set the argument to ".\SMBBlock.ps1"
        + Set the "Start in (optional):" field to the script folder in the FSRM config folder you provided earlier (normally C:\FSRM\)
5. Test!

##How it works
FSRM provides two different avenues to protecting against ransomware infections: bait, and detection. 
###Bait
Most ransomware infections will attempt to encrypt any file they have access to, regardless of whether that file is stored locally, or on a network share (even hidden shares are vulnerable).
This script will retreive a list of all the folders that are shared from the server, create a pair of hidden honeypot folders filled with fake files, and then configure FSRM to monitor these folders for any activity. 
By keeping the folders hidden, users will not see them, but ransomware infections will--and as soon as they attempt to modify any of the files within a honeypot folder, FSRM will send an e-mail and log an event to the Windows Event log. 
You can then create a scheduled task to watch for these events, and block SMB access for the infected user.

* Why are two honeypot folders created? 
    Most ransomware infections start encrypting files in alphabetical order, which is why the first folder created is "___Honeypot". However, some infections work in reverse order, hence the second folder, "zzz___Honeypot". 
    This ***should*** ensure that your honeypot folders are encrypted before an actual data.
* Why are so many files created in each honeypot folder? 
    Because it takes time for FSRM to recognize that a ransomware infection is taking place and then lock the offending users out. The more files (and the larger the files) that the ransomware has to infect, the longer it will take before it starts infecting actual files.

###Detection
Experiant is a Canadian IT firm that maintains a publicly accessible list of known ransomware extensions. FSRM can be configured to watch for these extensions, and alert admins & users if a matching file is detected. 
This script will check the Experiant list every Tuesday at 9AM for new patterns, and update the FSRM file groups if neccessary. It will also e-mail you a list of any new (or removed) patterns. 

##To-Do
* Add support for Server 2008 & Server 2008R2
* Improve documentation
* Add error handling & input validation
* Automatically create SMBBlocker task

##What it does
* Collects initial setup information:
    * User Credentials are used to create a scheduled task that downloads a list of  the latest ransomware extensions, and then update the FSRM File group.
    * STMP information is used to configure e-mail alerting. Anytime a file with a possible ransomware extension is detected, FSRM will e-mail both an admin, and the user that created the file. 
* Checks if FSRM is already installed
     * If FSRM is not installed, it will be installed, and the default file screens will be removed
* Create honeypot folders
    * Retreive a list of every SMB share on the local server (excluding the built-in windows shares)
    * Allow the user to select which shares should have honeypot folders
    * The user will be prompted to set a size for each honeypot folder--


        


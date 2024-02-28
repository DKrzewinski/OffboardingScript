# OffboardingScript

## Overview
This PowerShell script is designed for offboarding users in on-premises and Microsoft 365 hybrid environments. 
It automates various offboarding tasks such as disabling Active Directory (AD) user accounts, generating reports, forwarding emails, and handling Microsoft 365 (O365) related activities.

## Prerequisites
PowerShell: Ensure that PowerShell is installed on the system where the script will run.
Active Directory Module: The Active Directory PowerShell module must be available. This script uses the ActiveDirectory module for on-premises AD operations.
AzureAD Module: The AzureAD module is required for Microsoft 365 operations. Make sure to install it using the Install-Module -Name Az command.
Microsoft Teams PowerShell Module: The MicrosoftTeams module is necessary for managing Microsoft Teams. Install it with:

```
Install-Module -Name PowerShellGet -Force -AllowClobber
Install-Module -Name MicrosoftTeams -Force -AllowClobber
```

## Configuration
The script includes various configuration parameters that need to be set before running:

**$Global:transcriptPath**: Path to store transcript logs.

**$Global:PostOffboardSet**: Set to 0 if not using post-offboarding script.

**$Global:Path_SAVE**: Path for storing post-offboarding data.

**$Global:UsersOU**: Specify the Users Organizational Unit (OU) in AD.

**$Global:ADUserReportPath**: Path to store AD user reports.

**$Global:EmailDomain**: Email domain for checking manual email forwarding.

**$Global:MoveOffboardedOU**: OU where offboarded user objects will be moved.

**$Global:emailSmtpServer**: SMTP server for email notifications.

**$Global:emailFrom**: Email address for sending notifications.

**$Global:emailBCC**: BCC email for notifications if needed.

## Usage
Run the script in a PowerShell environment with the necessary modules installed.
The script will prompt the user to select a user for offboarding through a GUI.
It performs various tasks such as disabling the AD account, generating reports, forwarding emails, and handling O365-related actions.
The user will be moved to the specified offboarded OU in AD.
Detailed logs and reports will be generated in the specified paths.

## Notes
Ensure that the account running the script has the necessary permissions (HelpDeskAdmins or Domain Admins).
Review and customize email notification content in the script as needed.
For Microsoft Teams offboarding, the user is removed from all teams they are a member of.

### Additional Information
Author: **Damian Krzewinski**

Version: 1.0

Last Updated: **[28-Feb-2024]**

Please review and update the script parameters and configurations according to your organization's requirements before running it.
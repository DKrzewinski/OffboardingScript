# SETTINGS
$Global:transcriptPath = "\\Location\Offboarding\Reports\Audit\" # Transciption file path
$Global:PostOffboardSet = 0 # Do you want post-offboarding to complete as well? (needs post-offboarding script)
$Global:Path_SAVE = "\\Location\Offboarding\POST-Offboarding\Data\OffboardedUsersToProcess.csv" # Path for post-offboarding data file
$Global:UsersOU = "OU=NAME??,DC=ad,DC=domain,DC=com" # Specify users OU
$Global:ADUserReportPath = "\\location\Offboarding\Reports\Users\" # AD User report location
$Global:EmailDomain = "*@domain.com*" # Specify email domain to check for manual email forward
$Global:MoveOffboardedOU = "OU=Disabled - Move accounts here,OU=Users,DC=ad,DC=domain,DC=com" # Specify which OU to put offboarded user objects to
$Global:emailSmtpServer = "domain-com.mail.protection.outlook.com" # Specify SMTP server to use for email notifications
$Global:emailFrom = "from-email@domain.com" # Specify which email address will the notification come from
$Global:emailBCC = "bcc-email@domain.com" # Specify BCC email for notifications if needed
$emailBody = @"
$managerFirstName,<br>
<br>
This is an automated email to inform you of offboarding procedures performed on <b>$selecteduserName's</b> account. <br>
$($selectedUserFirstName)'s offboarding was requested by HR and performed by the Technology Operations team. <br>
<br>
Please see below for details:
<ul>
<li>Emails sent to $selecteduserEmail will now forward to you.</li>
<li>Emails will no longer be delivered to $($selectedUserFirstName)'s mailbox.</li>
</ul>
Additionally, please see the below list of extended offboarding activities scheduled to be performed in the future:
<ul>
<li>On <b>$date27</b>, any recurring meetings for which $selectedUserFirstName was the <u>organizer</u> will be cancelled. Meeting participants will receive cancellation notices.</li>
<li>On <b>$date30</b>, $($selectedUserFirstName)'s email address will be deleted and $($selectedUserFirstName)'s mailbox will be archived but still accessible to you if needed. <br>
</ul></li>
Additional details will be provided to you in a follow-up notification on <b>$date27</b>, at which time you may request an extension of $($selectedUserFirstName)'s email address and forwarding if needed.<br>
<br>
If you would like to stop the forwarding of email to you, request emails be forwarded to someone else, or if you need any assistance with access to this user's data, please open a new request on the Service Center <a href="https://link.com">here</a>.<br>
<br>
Thank you,<br>
<br>
Technology Operations Team
"@ # Email notification message (Please note if you specify different email [not managers] another version of this emailBody will be run on line 415)

<#
.SYNOPSIS
Offboarding script for on-prem and 365 hybrid environments.

.DESCRIPTION
Offboarding script for on-prem and 365 hybrid environments. This script has references to another script (post-offboarding), but can be run without it if you leave the PostOffboardSet variable at 0.
#>
function Load-Module ($m) {

    # If module is imported say that and do nothing
    if (Get-Module | Where-Object { $_.Name -eq $m }) {
        write-host "Module $m is already imported."
    }
    else {

        # If module is not imported, but available on disk then import
        if (Get-Module -ListAvailable | Where-Object { $_.Name -eq $m }) {
            Import-Module $m -Verbose
            cls
        }
        else {

            # If module is not imported, not available on disk, but is in online gallery then install and import
            if (Find-Module -Name $m | Where-Object { $_.Name -eq $m }) {
                Install-Module -Name $m -Force -Verbose -Scope CurrentUser
                Import-Module $m -Verbose
                cls
            }
            else {

                # If the module is not imported, not available and not in the online gallery then abort
                write-host "Module $m not imported, not available and not in an online gallery, exiting."
                EXIT 1
            }
        }
    }
}

function Transcribe { 
    #transcript logging
    $currentAdmin = $env:Username
    $adminPC = $env:ComputerName
    $date = Get-Date -f yyyy-MM-dd_hh-mm-ss
    $transcriptFile = $transcriptPath + $currentAdmin + "_" + "$adminPC" + "_" + $date + ".txt" 
    Start-Transcript -Path $transcriptFile -noclobber
}

Function SaveInfoForPostOffboarding($u){
    
    [System.Collections.ArrayList]$Global:Users_SAVE = Import-Csv $Path_SAVE
    
    $ObjectId_SAVE = $u.ObjectGUID
    $AccountEnabled_SAVE = $u.Enabled
    $DisplayName_SAVE = $u.Name
    $Global:GivenName_SAVE = $u.GivenName
    [DateTime]$DateToTakeAction_SAVE = (get-date).AddDays(23)
    $Mail_SAVE = $u.UserPrincipalName
    
    $SupervisorToNotify_SAVE = (Get-ADUser -Identity (Get-ADUser -Identity $($u.Manager)).DistinguishedName -Properties mail).mail
    Write-Host    
    try{
        $ForwardingSmtpAddress_SAVE = ((Get-Mailbox $u.SamAccountName | select ForwardingSmtpAddress).ForwardingSmtpAddress).Split(":")[1] | Out-Null
        }catch{
        $ForwardingSmtpAddress_SAVE = ""
        }
    $MailNickName_SAVE = $u.SamAccountName
    $OnPremisesSecurityIdentifier_SAVE = $u.SID.Value
    $ProxyAddresses_SAVE = "System.Collections.Generic.List`1[System.String]"
    $Global:Surname_SAVE = $u.Surname
    $UserPrincipalName_SAVE = $u.UserPrincipalName

    $newRow_SAVE = New-Object PsObject -Property @{ ObjectId = $ObjectId_SAVE ; ObjectType = "User" ; AccountEnabled = "FALSE" ; DisplayName = $DisplayName_SAVE ; GivenName = $GivenName_SAVE ; ActionToTake = "iniNOTIFY" ; DateToTakeAction = $DateToTakeAction_SAVE ; Mail = $Mail_SAVE ; SupervisorToNotify = $SupervisorToNotify_SAVE ; ForwardingSmtpAddress = $ForwardingSmtpAddress_SAVE; MailNickName = $MailNickName_SAVE ; OnPremisesSecurityIdentifier = $OnPremisesSecurityIdentifier_SAVE ; ProxyAddresses = "System.Collections.Generic.List`1[System.String]" ; Surname = $Surname_SAVE ; UserPrincipalName = $UserPrincipalName_SAVE ; UserType = "Member" }
    
    $Users_SAVE.Add($newRow_SAVE) | Out-Null
    
    $Users_SAVE | Export-Csv -Path $Path_SAVE -NoTypeInformation
}

# Start transcript
Transcribe

# Import the ActiveDirectory module
Load-Module "ActiveDirectory"

Write-Host "=========================================================================================="
Write-Host
Write-Host "Checking if your currently logged on account is a member of HelpDeskAdmins or DomainAdmins"
Write-Host

$global:CurUser = $env:USERNAME
$global:curUserAllprops = Get-ADUser $CurUser -Properties *
$curUserGrps = Get-ADUser $CurUser -Properties * | Select-Object -ExpandProperty MemberOf
$global:Groups = foreach ($group in $curUserGrps) { Get-ADGroup $group }
$global:HelpDeskAdmins = Get-ADGroup "HelpDeskAdmins" | Select-Object SID # Script needs to be run as a user in either HelpDeskAdmins or Domain Admins group
$global:DomainAdmins = Get-ADGroup "Domain Admins" | Select-Object SID # Script needs to be run as a user in either HelpDeskAdmins or Domain Admins group

# Checking if the script is run as admin account
Write-Host "Checking Admin Access..."
Write-Host
if (($Groups.sid -notcontains $HelpDeskAdmins.sid) -and ($Groups.sid -notcontains $DomainAdmins.sid)) {
    Write-Host "User is not in HelpDeskAdmins or DomainAdmins. Try re-opening as another user with such permissions. or escalate to SysAdmin to confirm AD permissions"
    Write-Host "Auto closing in 5 seconds" ; Start-Sleep -seconds 5 ; exit 
}
else {
    Write-Host "Access Verified."
    Write-Host
}

# Get all users from Users OU
$users = Get-ADUser -Filter * -SearchBase $UsersOU -Properties Manager, Title

# Create a GUI for user selection
$selectedUser = $users | Out-GridView -Title "Select a user to offboard" -PassThru

# Saving SAM Account name and email
$sAMAccountName = $selectedUser.SamAccountName
$selecteduserEmail = (Get-ADUser -Identity $selectedUser.DistinguishedName -Properties mail).mail
$manager = (Get-ADUser -Identity $selectedUser.Manager)
$managerEmail = (Get-ADUser -Identity (Get-ADUser -Identity $($selectedUser.Manager)).DistinguishedName -Properties mail).mail

# Display the selected user's position and manager
$selecteduserName = $selectedUser.Name
$selectedUserFirstName = $selectedUser.GivenName
Write-Host "User: $($selecteduserName)"
Write-Host "Position: $($selectedUser.Title)"
Write-Host "SAMAccountName: $($sAMAccountName)"
Write-Host "Email: $($selecteduserEmail)"
$managerName = $manager.Name
$managerFirstName = $manager.GivenName
Write-Host
Write-Host "Manager: $($managerName)"
Write-Host "Managers email: $($managerEmail)"

# Ask for confirmation to offboard
Write-Host
$confirmation = Read-Host "Are you sure you want to offboard this user? (yes/no)"

#Set defaults to store offboarding infomation
$global:date = Get-Date -f yyyy-MM-dd_hh-mm-ss
$global:userFolder = $sAMAccountName + "_" + $date
$global:userADFile = $sAMAccountName + "_AD_" + $date + ".txt"
$global:inboxRulesFile = $sAMAccountName + "_InboxRules_" + $date + ".txt"
$global:GroupInfoFile = $sAMAccountName + "_GroupsReport_" + $date + ".txt"
$global:o365LicRreportFile = $sAMAccountName + "_O365Licenses_" + $date + ".txt"
$global:mailboxInfo = $sAMAccountName + "_O365Groups_" + $date + ".txt"
$global:subordinates = $sAMAccountName + "_SubordinatesChangedTo_" + $manager.GivenName + "_" + $manager.Surname + "_" + $date + ".txt"

# If confirmation is yes, offboard the user
if ($confirmation -eq "yes") {

    # Check with admin if he wants to forward the email to the manager
    $confirmation2 = Read-Host "Do you want to forward this user's email to the manager? (yes/no)"

    if ($confirmation2 -eq 'no') {
        # Check with admin if he wants to forward the email to someone else
        $confirmation3 = Read-Host "Provide email for the forward (leave blank if no forward required)"

        if ($confirmation3 -ne '') {
            while ($confirmation3 -notlike $EmailDomain) {
                Write-Host "Email is incorrect, provide a correct forward email. Must include $($EmailDomain)"
                $confirmation3 = Read-Host "Provide email for the forward"
            }
            try {
                $fwuser = Get-ADUser -Filter { EmailAddress -eq $confirmation3 }
                while ($fwuser -eq "" -or $fwuser -eq $null) {
                    write-host "Forward user not found. Try again!"
                    $confirmation3 = Read-Host "Provide email for the forward"
                    $fwuser = Get-ADUser -Filter { EmailAddress -eq $confirmation3 }
                }
            }
            catch {
                write-host "Error when grabbing forward user $($confirmation3)"
            }
        }
    }

    $creds = Get-Credential
    while((($creds.Password -eq $null) -or ($creds.Password.Length -eq '0')) -or ($creds.UserName -notlike $EmailDomain)){
        Clear-Host
        Write-Host "ERROR: Incorrect credentials, must contain $($EmailDomain) address"
		Write-Host
		Start-Sleep -seconds 5
        $creds = Get-Credential
    }
	
    Write-Host "Connecting to AzureAD..."
    Connect-AzureAD -Credential $creds | Out-Null

    Write-Host "Connecting to Exchange Online..."
    Connect-ExchangeOnline -Credential $creds | Out-Null

    Write-Host "Connecting to Microsoft Teams..."
    Connect-MicrosoftTeams -Credential $creds | Out-Null

    Write-Host
    Clear-Host

    # ==================================================================================================
    if($PostOffboardSet){
        Write-Host "Saving info for Post-Offboarding..."
        SaveInfoForPostOffboarding($selecteduser)
        Clear-Host
    }
    
	Write-Host "-----------------------------------------------------------------------------"
    Write-Host "Starting on-prem offboarding for $($selecteduserName) ($($selecteduserEmail))..."
	Write-Host "-----------------------------------------------------------------------------"
    Start-Sleep -seconds 2
    Write-Host

    # Disable the AD user account
    Disable-ADAccount -Identity $selectedUser.DistinguishedName
    Write-Host "User account disabled."

    # Generate and set a random password for the AD user
    $newPassword = ("V" + (New-Guid).Guid)
    Set-ADAccountPassword -Identity $selectedUser.SamAccountName -NewPassword (ConvertTo-SecureString -AsPlainText $newPassword -Force)
    Write-Host "Random password has been set."

    #Save all users AD groups
    
    $userGroups = Get-ADPrincipalGroupMembership $selectedUser.DistinguishedName
    
    mkdir ($ADUserReportPath + $global:userFolder) > $null
    
    $userGroups | Select-Object -ExpandProperty Name | Out-File -FilePath ($ADUserReportPath + $global:userFolder + "\" + $global:GroupInfoFile)
    Write-Host "Saved all user group memberships."

    # Remove all AD user groups
    $userGroups = Get-ADPrincipalGroupMembership $selectedUser.DistinguishedName
    foreach ($userGroup in $userGroups) {
        if ($userGroup.name -ne "Domain Users") {
            try {
                Remove-ADPrincipalGroupMembership -Identity $selectedUser.DistinguishedName -MemberOf $userGroup.DistinguishedName -ea 0 -Confirm:$false
            }
            catch {
                Write-Host "!!! $($userGroup.name) group could not be removed !!!"
            }
        }
    }
    Write-Host "Removed all user AD groups."

    #Get all subortinates and move to this user's manager
    $sub = Get-ADUser -Identity $selectedUser.SamAccountName -Properties directreports | select-object -ExpandProperty DirectReports
    $sub | Out-File -FilePath ($ADUserReportPath + $global:userFolder + "\" + $global:subordinates)
    foreach ($subordinate in $sub) { 
        try {
            $curSub = Get-ADUser -Identity $subordinate
            $subordinate | Set-ADUser -Manager $manager.DistinguishedName
        }
        catch {
            $subname = (Get-ADUser -Identity $subordinate).Name
            Write-Output "Couldn't change $($subname) manager to $($manager.DistinguishedName)"
        }
    }

    # Save all user attributes to a file
    $userAttributes = Get-ADUser -Identity $selectedUser.DistinguishedName -Properties *
    $userAttributes | Out-File -FilePath ($ADUserReportPath + $global:userFolder + "\" + $global:userADFile)

    #Clearing user attributes
    Write-Host 'Hiding from address book...'
    set-ADUser $samAccountName -Add @{msExchHideFromAddressLists = "TRUE" } -Confirm:$false	
    set-ADUser $samAccountName -replace @{msExchHideFromAddressLists = "TRUE" } -Confirm:$false
    Write-Host 'Set mailNickname attribute to sAMAccountName so that O365 will honor the synced msExchHideFromAddressLists attribute'
    Set-ADUser $samAccountName -Replace @{MailNickName = $sAMAccountName } -ea 0 -Confirm:$false
    Write-Host 'Clearing the attribute OfficePhone'
    set-ADUser $samAccountName -OfficePhone $null -ea 0 -Confirm:$false 
    Write-Host 'Clearing the attribute Office'
    set-ADUser $samAccountName -Office $null -ea 0 -Confirm:$false 
    Write-Host 'Clearing the attribute POBox'
    set-ADUser $samAccountName -POBox $null -ea 0 -Confirm:$false 
    Write-Host 'Clearing the attribute State'
    set-ADUser $samAccountName -State $null -ea 0 -Confirm:$false 
    Write-Host 'Clearing the attribute city'
    set-ADUser $samAccountName -city $null -ea 0 -Confirm:$false  
    Write-Host 'Clearing the attribute manager'
    set-ADUser $samAccountName -manager $null -ea 0 -Confirm:$false 
    Write-Host 'Clearing the attribute ipPhone'
    set-ADUser $samAccountName -clear ipPhone -ea 0 -Confirm:$false 
    Write-Host 'Clearing the attribute Title'
    set-ADUser $samAccountName -clear Title -ea 0 -Confirm:$false 
    Write-Host 'Clearing the attribute department'
    set-ADUser $samAccountName -clear department -ea 0 -Confirm:$false 
    Write-Host 'Clearing the attribute company'
    set-ADUser $samAccountName -clear company -ea 0 -Confirm:$false 
    Write-Host 'Clearing the attribute ipPhone'
    set-ADUser $samAccountName -clear ipPhone -ea 0 -Confirm:$false 
    Write-Host 'Clearing the attribute PostalCode'
    set-ADUser $samAccountName -clear PostalCode -ea 0 -Confirm:$false 
    Write-Host 'Clearing the attribute StreetAddress'
    set-ADUser $samAccountName -clear StreetAddress -ea 0 -Confirm:$false 
    Write-Host 'Clearing the attribute telephoneNumber'
    set-ADUser $samAccountName -clear telephoneNumber -ea 0 -Confirm:$false 
    Write-Host 'Clearing the attribute facsimileTelephoneNumber'
    set-ADUser $samAccountName -clear facsimileTelephoneNumber -ea 0 -Confirm:$false 
    Write-Host 'Clearing the attribute fax'
    set-ADUser $samAccountName -fax $null -ea 0 -Confirm:$false 
    Write-Host 'Clearing the attribute HomePhone'
    set-ADUser $samAccountName -clear HomePhone -ea 0 -Confirm:$false 
    Write-Host 'Clearing the attribute mobile'
    set-ADUser $samAccountName -clear mobile -ea 0 -Confirm:$false 
    Write-Host 'Clearing the attribute MobilePhone'
    set-ADUser $samAccountName -MobilePhone $null -ea 0 -Confirm:$false 
    Write-Host 'Clearing the attribute pager'
    set-ADUser $samAccountName -clear pager -ea 0 -Confirm:$false

    # Moving user account to "Disabled - Move accounts here"
    Move-ADObject -Identity $selectedUser -TargetPath $MoveOffboardedOU
    Write-Host 'Moved user account to specified OU ($($MoveOffboardedOU))'

    # Delete ADM account if exists
    Write-Host "Looking for ADM account..."
    $admacc = "adm." + $selectedUser.SamAccountName
    try
    {
        $adm = Get-ADUser $admacc
        Write-Host "Deleting ADM account: $($adm.SamAccountName)"
        try
        {
            Remove-ADUser -Identity $adm -ea 0 -Confirm:$false
            Write-Host "Account $($adm.SamAccountName) deleted successfully"
        }catch
        {
            Write-Host "ERROR: Account $($adm.SamAccountName) could NOT be deleted"
        }
    }catch
    {
        Write-Host "ADM account not found"
    }

    # ==================================================================================================

	Write-Host
	Write-Host "-----------------------------------------------------------------------------"
    Write-Host "Starting O365 offboarding for $($selecteduserName) ($($selecteduserEmail))..."
	Write-Host "-----------------------------------------------------------------------------"
    Start-Sleep -seconds 5

    $oemail = Get-Recipient -Identity $selecteduserEmail

    # Change mailbox to a shared mailbox
    Set-Mailbox -Identity $oemail.Alias -Type Shared
    Write-Host "Mailbox changed to a shared mailbox"

    # Forwarding user email to the manager
    if ($confirmation2 -eq "yes") {
        Write-Host "Forwarding user email to the manager $($managerEmail)"
        set-Mailbox -Identity $oemail.Alias -ForwardingSMTPAddress $managerEmail

        # Send email notification
        Write-Host "fwd $selecteduserEmail to $managerEmail"
		
        #set-Mailbox -Identity $selecteduserEmail -ForwardingSMTPAddress $managerEmail
        $mailboxprimarysmtpaddress = $mailbox.PrimaryPrimarySmtpAddress
        $emailTo = $managerEmail
        $global:date27 = (get-date).AddDays(27).ToString('MM/dd/yyyy')
        $global:date30 = (get-date).AddDays(30).ToString('MM/dd/yyyy')
		
        $emailSubject = "[IT Notice] $selecteduserName has been offboarded"

        Send-MailMessage -To $emailTo -bcc $emailBCC -From $emailFrom -Subject $emailSubject -Body $emailBody -SmtpServer $emailSmtpServer -BodyAsHtml        
     
    }
    else {
        if ($confirmation3 -ne '') {
            Write-Host "Forwarding user email to the $($confirmation3)"
            set-Mailbox -Identity $oemail.Alias -ForwardingSMTPAddress $confirmation3

            # Send email notification
            Write-Host "fwd $selecteduserEmail to $confirmation3"
		
            #set-Mailbox -Identity $selecteduserEmail -ForwardingSMTPAddress $managerEmail
            $mailboxprimarysmtpaddress = $mailbox.PrimaryPrimarySmtpAddress
            $emailTo = $confirmation3
            $fwname = (Get-ADUser -Filter { EmailAddress -eq $confirmation3 }).GivenName
		
            $emailSubject = "[IT Notice] $selecteduserName has been offboarded"
            $emailBody = @"
$fwname,<br>
<br>
This is an automated email to inform you of offboarding procedures performed on <b>$selecteduserName's</b> account. <br>
$($selectedUserFirstName)'s offboarding was requested by HR and performed by the Technology Operations team. <br>
<br>
Please see below for details:
<ul>
<li>Emails sent to $selecteduserEmail will now forward to you.</li>
<li>Emails will no longer be delivered to $($selectedUserFirstName)'s mailbox.</li>
</ul>
Additionally, please see the below list of extended offboarding activities scheduled to be performed in the future:
<ul>
<li>On <b>$date27</b>, any recurring meetings for which $selectedUserFirstName was the <u>organizer</u> will be cancelled. Meeting participants will receive cancellation notices.</li>
<li>On <b>$date30</b>, $($selectedUserFirstName)'s email address will be deleted and $($selectedUserFirstName)'s mailbox will be archived but still accessible to you if needed. <br>
Additional details will be provided to you in a follow-up notification on $date27, at which time you may request an extension of $($selectedUserFirstName)'s email address and forwarding if needed.</li>
</ul>
If you would like to stop the forwarding of email to you, request emails be forwarded to someone else, or if you need any assistance with access to this user's data, please open a new request on the Service Center <a href="https://link.com">here</a>.<br>
<br>
Thank you,<br>
<br>
Technology Operations Team
"@
     
            Send-MailMessage -To $emailTo -bcc $emailBCC -From $emailFrom -Subject $emailSubject -Body $emailBody -SmtpServer $emailSmtpServer -BodyAsHtml
        }
    }
    
    # Save all groups from 365 to a file
    Write-Host "Saving all 365 groups to a file..."
    $ogroups = Get-AzureADUserMembership -ObjectId $oemail.PrimarySmtpAddress
    $ogroups | Out-File -FilePath ($ADUserReportPath + $global:userFolder + "\" + $global:mailboxInfo)

    # Remove all groups membership
    Write-Host "Removing all groups from the user..."
    $oemailobjectid = (Get-AzureADuser -objectid $oemail.PrimarySmtpAddress).objectid

    foreach ($Ogroup in $ogroups.ObjectId) {
        try { 
            Remove-AzureADGroupMember -ObjectId $Ogroup -MemberId $oemailobjectid -ea 0 -Confirm:$false
        }
        catch {
            # write-host "WARNING: $((Get-AzureADGroup -ObjectId $ogroup).displayname) membership cannot be removed via Azure cmdlets."
            # write-host "Trying to remove with Remove-DistributionGroupMember"
            try {
                $tmp = (Get-AzureADGroup -ObjectId $ogroup).mail
                Remove-DistributionGroupMember -identity $tmp -member $oemail.PrimarySmtpAddress -BypassSecurityGroupManagerCheck -ea 0 -Confirm:$false
            }
            catch {
                $tmp = (Get-AzureADGroup -ObjectId $ogroup).displayname
                # write-host "!!! $($selectedUser.Name) cannot be removed from $($tmp) !!!"
            }
        }
    }
    
    # Save inbox rules and remove them
    Write-Host "Saving inbox rules to a file..."
    $rules = Get-InboxRule -Mailbox $oemail.PrimarySmtpAddress 
    $rules | Out-File -FilePath ($ADUserReportPath + $global:userFolder + "\" + $global:inboxRulesFile)
    Write-Host "Removing all inbox rules..."
    foreach ($rule in $rules) {
        Remove-InboxRule -Identity $rule.Identity -Confirm:$false
    }

    # Save license info & remove licenses
    Write-Host "Saving email licenses SKU ID to a file..."
    $licenses = (Get-AzureADUser -ObjectId $oemail.PrimarySmtpAddress).assignedlicenses
    (Get-AzureADUser -ObjectId $oemail.PrimarySmtpAddress).assignedlicenses.skuid | Out-File -FilePath ($ADUserReportPath + $global:userFolder + "\" + $global:o365LicRreportFile)
    Write-Host "Removing all licenses..."
    $userUPN = $selectedUser.UserPrincipalName
    $userList = Get-AzureADUser -ObjectID $userUPN
    $Skus = $userList | Select-Object -ExpandProperty AssignedLicenses | Select-Object SkuID
    if ($userList.Count -ne 0) {
        if ($Skus -is [array]) {
            $licenses = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses
            for ($i = 0; $i -lt $Skus.Count; $i++) {
                $licenses.RemoveLicenses += (Get-AzureADSubscribedSku | Where-Object -Property SkuID -Value $Skus[$i].SkuId -EQ).SkuID   
            }
            Set-AzureADUserLicense -ObjectId $userUPN -AssignedLicenses $licenses
        }
        else {
            $licenses = New-Object -TypeName Microsoft.Open.AzureAD.Model.AssignedLicenses
            $licenses.RemoveLicenses = (Get-AzureADSubscribedSku | Where-Object -Property SkuID -Value $Skus.SkuId -EQ).SkuID
            Set-AzureADUserLicense -ObjectId $userUPN -AssignedLicenses $licenses
        }
    }

    # Removing users from all Microsoft Teams
    if((Get-Team -User $selectedUser.UserPrincipalName) -ne $null)
    {
        $teams = Get-Team -User $selectedUser.UserPrincipalName
        foreach ($team in $teams)
        {
            Remove-TeamUser -GroupId $team.GroupId -User $selectedUser.UserPrincipalName
            Write-Output "$($selectedUser.Name) is removed from team $($team.DisplayName)"
        }
        Write-Output "$($selectedUser.Name) has been removed from $($teams.Count) Team(s)."
    }
    else 
    {
        Write-Output "$($selectedUser.Name) is not member of a team"
    }

    Write-Host "User has been offboarded.`n`n"
    Write-Host "Report files can be found here:"
    $UserFileReportLocation = $ADUserReportPath + $($global:userFolder)
    Write-Host $UserFileReportLocation
    Start-Sleep -seconds 2
}
else {
    Write-Host
    Write-Host "Offboarding cancelled."
}
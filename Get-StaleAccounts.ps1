Function Remove-StaleAccounts {
    <#
    .SYNOPSIS
    Remove accounts that are no longer actively using a computer.

    .DESCRIPTION
    connects to a remote computer and collects the folder names within
    c:\users\ which matches up with ADUser object SamAccountName property
    and uses the folder names to find accounts that are no longer actively using 

    .PARAMETER ComputerName
    System.String ComputerName
    name of remote computer. This parameter is mandatory.

    .INPUTS
    System.String ComputerName
    None You cannot pipe objects to this function.

    .NOTES
    Computer validation check
	- Try to create remote session; throw error and stop script if it fails

	1. Gets folders on c:\users of the remote computer
	2. Runs aduser against the folder names (sam account names)
	3. Identify user folders that can be removed
		a. not found in active directory - clearNotInAD
		b. home location is different from computer - clearNotAtStore
			i. Parse OU location of workstation to begin script
			ii. Compare region OU and store OU to user
			iii. Put users not matching store in list
		c. Users in deprovisioning - clearRecentlyLeft
	4. Default to just display results
    Options to clear a certain group, or clearAll

    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True)]
        [string]$ComputerName
    )
        
    Begin {
        # initialize pssession for use during script
        # script will fail if unable to initiate a pssession
        $remoteSession = new-pssession -ComputerName $ComputerName -ErrorAction Stop
        # setup output structure
        $Output = [pscustomobject]@{
            LocalUserFolders        = @() 
            ADUserResults           = @()
            UsersNotInAD            = @()
            UsersInDeprovisioningOU = @()
            UsersAtDifferentStore   = @() 
            WorkstationADObject     = $null
        }
        # gets remote computer AD object
        # used to check if user is at same store
        $Output.WorkstationADObject = Get-ADComputer -Filter { Name -like $ComputerName }
    }
    
    Process {
        $retrieveLocalFoldersScriptBlock = {
            # system accounts should not be deleted)
            $systemaccounts = @(
                'administrator',
                'Public',
                'default',
                'DOMAIN\administrator',
                'NetworkService',
                'LocalService',
                'systemprofile') 
            # folder names array thas will be the sent to $Output.LocalUserFolders
            $folders = @()
            $userFolders = Get-ChildItem "C:\Users" |
            Where-Object { $_.Name -notin $systemaccounts } 

            $userFolders | ForEach-Object {
                # $_ = folder in $userFolders
                $folders += $_
            }

            # outputting array of folder names within c:\users
            Write-Output $folders
        }
        # collect list of folder names within c:\users
        $Output.LocalUserFolders = Invoke-Command -Session $remoteSession -ScriptBlock $retrieveLocalFoldersScriptBlock -ErrorAction Stop


        # Create a filter string to find active users not in the $Output.LocalUserFolders list
        # building this filter allows for one call to AD vs one for each user
        $filter = $($Output.LocalUserFolders | ForEach-Object { "SamAccountName -eq '$($_.Name)'" }) -join " -or "
        # save users found in Active Directory to output
        $Output.ADUserResults = Get-ADUser -Filter $filter -Properties DisplayName
        

        # extracts SamAccountNames from ADUserResults
        $usersNames = $Output.ADUserResults |
        Select-Object -ExpandProperty samaccountname
        # compares LocalUserFolders and usersNames variables to get
        # list of folders of users that are not in active directory
        # Filter to only get items from LocalUserFolders not in usersNames
        # (indicated by <= in SideIndicator)
        $Output.UsersNotInAD = Compare-Object -ReferenceObject $Output.LocalUserFolders -DifferenceObject $usersNames -IncludeEqual |
        Where-Object SideIndicator -eq '<=' |
        Select-Object -ExpandProperty InputObject


        $workstationStore = $Output.WorkstationADObject.DistinguishedName.Split(",")[2] # 3 alpha 
        $workstationRegion = $Output.WorkstationADObject.DistinguishedName.Split(",")[3] # 2 alpha 
        foreach ($user in $Output.ADUserResults) {
            # gets 3rd block from fqdn which is usually the store block
            # will be used to compare to workstation store ou
            $userStore = $user.distinguishedname.Split(",")[2]
            switch ($userStore) {
                # if user store code = store code continue to next user
                # $workstationStore { break }
                # if store code matches region user is in wrong OU (not in a store OU)
                # need to extract TM store location from display name: first last (RR SSS) R=region, S=store
                $workstationRegion {
                    if ($user.DisplayName -match "\((.+?)\)") {
                        $values = $matches[1] -split " "
                        $storeCode = $values[1]
                        if ($storeCode -eq $workstationStore) { break }
                        else {
                            $Output.UsersAtDifferentStore += $user
                        }
                    }
                }
                # find users in deprovisioning OU
                "OU=DEPROVISIONING" { $Output.UsersInDeprovisioningOU += $user }
                Default {}
            }
        }
        
        Write-Output $Output
    }
    
    End {
        # cleanup remote session
        Remove-PSSession $remoteSession
    } 
}

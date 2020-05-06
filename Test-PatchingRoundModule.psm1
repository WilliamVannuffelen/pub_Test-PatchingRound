# generate timestamp for logging
function Get-TimeStamp {
    return Get-Date -f "yyyy-MM-dd HH:mm:ss -"
}

# helper function to compare osit exclusion list to services
function Test-Match{
    [cmdletBinding()]
    param(
        [string] $inputString,
        [object] $regexPatternList
    )
    foreach($pattern in $regexPatternList){
        if($inputString -like $pattern){
            return $true
        }
    }
    return $false
}

# helper function to check whether service start type is 'true' automatic vs Automatic (Delayed Start) or Automatic (Triggered)
function Test-ServiceStartTypeAuto{
    [cmdletBinding()]
    param(
        [string] $serviceName,
        [object] $psSession
    )

    $registryPath = "HKLM:\SYSTEM\CurrentControlset\Services\$serviceName"
    $registrySubKeyPath = "$registryPath\TriggerInfo\"

    $scriptBlock = {
        # check if Auto/Delayed
        if((Get-Item -path $using:registryPath).property -contains 'DelayedAutoStart'){
            if((Get-ItemProperty -Path $using:registryPath).delayedAutoStart -eq 1){
                return $false
            }
        }
        # check if Auto/Triggered
        if(Test-Path -Path $using:registrySubKeyPath){
            return $false
        }
        return $true
    }

    # check if Auto/Delayed
    try{
        $startTypeAutomatic = Invoke-Command -Session $psSession -ScriptBlock $scriptBlock -ErrorAction Stop
        return $startTypeAutomatic
    }
    catch{
        # if error in checking start type, assume it is automatic
        return $true
    }
}

function Get-ServerIpAddress{
    [cmdletBinding()]
    param(
        [string] $computerName
    )
    $logData = New-Object System.Collections.ArrayList

    try{
        [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Querying DNS for IP address.")
        $ipHostEntry = [System.Net.DNS]::GetHostByName($computerName)
        $ipAddress = ($ipHostEntry.addressList -join ',')
        [void]$logData.Add("$(Get-TimeStamp) INFO: $computername - Queried DNS for IP address.")
    }
    catch [System.Management.Automation.MethodInvocationException]{
        if($_.exception -like "*No such host is known*"){
            $ipAddress = $null
            [void]$logData.Add("$(Get-TimeStamp) INFO: $computername - Failed to get IP address. FQDN not known in DNS.")
        }
        else{
            $ipAddress = $null
            [void]$logData.Add("$(Get-TimeStamp) ERROR: $computername - Failed to get IP address")
            [void]$logData.Add($_.exception.message)
        }
    }
    catch{
        $ipAddress = $null
        [void]$logData.Add("$(Get-TimeStamp) ERROR: $computername - Failed to get IP address")
        [void]$logData.Add($_.exception.message)
    }
    return $ipAddress, $logData
}

function Connect-PsSessionCustom{
    [cmdletbinding()]
    param(
        [string] $computerName,
        [PSCredential] $domainCredentials,
        [PSCredential] $workgroupCredentials
    )
    $logData = New-Object System.Collections.ArrayList

    # try initiating WinRM/Kerberos PS session for domain target
    try{
        [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Starting PS session (Kerberos).")
        $psSession = New-PsSession -ComputerName $computerName -Authentication Kerberos -Credential $domainCredentials -ErrorAction Stop
        [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Started PS session (Kerberos).")
        $kerberosPsSessionOk = $true
    }
    catch{
        [void]$logData.Add("$(Get-Timestamp) ERROR: $computerName - Failed to start PS session (Kerberos).")
        [void]$logData.Add($_.Exception.Message)
        $kerberosPsSessionOk = $false
    }

    # if failed to initiate, try WinRM/NTLM CIM session for known workgroup targets
    if($kerberosPsSessionOk -eq $false){
        $defaultCredList = @(
            'workgroup-server-0001'
            'workgroup-server-0002'
        )
        # WinRM to FQDN of local host fails due to default security config. localhost is used as a workaround.
        if($computerName.Split('.')[0] -eq $env:computerName){
            try{
                [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Starting PS session (NTLM).")
                $psSession = New-PsSession -ComputerName localhost -Authentication Negotiate -ErrorAction Stop
                [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Started PS session (NTLM).")
                $ntlmPsSessionOk = $true
            }
            catch{
                [void]$logData.Add("$(Get-Timestamp) ERROR: $computerName - Failed to start PS session (NTLM).")
                [void]$logData.Add($_.Exception.Message)
                $ntlmPsSessionOk = $false
            }
        }
        # if target workgroup machine credentials match script hosts', pass current context credentials
        elseif($computerName.Split('.')[0] -in $defaultCredList){
            try{
                [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Starting PS session (NTLM).")
                $psSession = New-PsSession -ComputerName $computerName -Authentication Negotiate -ErrorAction Stop
                [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Started PS session (NTLM).")
                $ntlmPsSessionOk = $true
            }
            catch{
                [void]$logData.Add("$(Get-Timestamp) ERROR: $computerName - Failed to start PS session (NTLM).")
                [void]$logData.ADd($_.Exception.Message)
                $ntlmPsSessionOk = $false
            }
        }
        # if alternate credentials were provided, try those
        elseif($workgroupCredentials -is [psCredential]){
            try{
                [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Starting PS session (NTLM).")
                $psSession = New-PsSession -ComputerName $computerName -Authentication Negotiate -Credential $workgroupCredentials -ErrorAction Stop
                [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Started PS session (NTLM).")
                $ntlmPsSessionOk = $true
            }
            catch{
                [void]$logData.Add("$(Get-Timestamp) ERROR: $computerName - Failed to start PS session (NTLM).")
                [void]$logData.Add($_.Exception.Message)
                $ntlmPsSessionOk = $false
            }
        }
        else{
            [void]$logData.Add("$(Get-Timestamp) ERROR: $computerName - No local account credentials provided for NTLM authentication. PS Session was not started. No checks will occur.")
            $ntlmPsSessionOk = $false
        }
    }

    if($kerberosPsSessionOk -eq $true -or $ntlmPsSessionOk -eq $true){
        $psSessionObject = [PSCustomObject]@{
            psSessionOk = $true
            psSession = $psSession
        }
    }
    else{
        $psSessionObject = [PSCustomObject]@{
            psSessionOk = $false
            psSession = $false
        }
    }

    return $psSessionObject, $logData
}

function Test-SystemType{
    [cmdletBinding()]
    param(
        [string] $computerName,
        [object] $psSession
    )
    $logData = New-Object System.Collections.ArrayList

    try{
        [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Querying Win32_ComputerSystem.")
        $csCimInstance = Invoke-Command -Session $psSession -ScriptBlock {Get-CimInstance -ClassName Win32_ComputerSystem -OperationTimeOutSec 60 -ErrorAction Stop} -ErrorAction Stop
        [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Queried Win32_ComputerSystem.")

    }
    catch{
        [void]$logData.Add("$(Get-Timestamp) ERROR: $computerName - Failed to query Win32_ComputerSystem.")
        [void]$logData.Add($_.Exception.Message)
        $systemType = 'unknown'
        #return 'unknown'
    }

    if($csCimInstance.manufacturer -like "VMware*"){
        $systemType = 'virtual'
        #return 'virtual'
    }
    else{
        $systemType = 'physical'
        #return 'physical'
    }
    return $systemType, $logData
}

function Test-RebootTime{
    [cmdletbinding()]
    param(
        [string] $computerName,
        [dateTime] $patchingStartTime,
        [object] $psSession
    )
    $logData = New-Object System.Collections.ArrayList

    try{
        [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Querying Win32_OperatingSystem.")
        $osCimInstance = Invoke-Command -Session $psSession -ScriptBlock {Get-CIMInstance -ClassName Win32_OperatingSystem -OperationTimeoutSec 60 -ErrorAction Stop} -ErrorAction Stop
        [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Queried Win32_OperatingSystem.")
    }
    catch{
        [void]$logData.Add("$(Get-Timestamp) ERROR: $computerName - Failed to query Win32_OperatingSystem.")
        [void]$logData.Add($_.Exception.Message)

        $rebootStatus = [PSCustomObject]@{
            rebootQuerySuccessful = $false
            osVersion = "unknown"
            patchingStartTime = $patchingStartTime
            lastBootTime = "unknown"
            rebootedAfterPatching = "unknown"
        }

        return $rebootStatus, $logData
    }

    $lastBootTime = $osCimInstance.lastBootUpTime
    $rebootedAfterPatching = ($lastBootTime -gt $patchingStartTime)

    $rebootStatus = [PSCustomObject]@{
        rebootQuerySuccessful = $true
        osVersion = $osCimInstance.name.Split('|')[0]
        patchingStartTime = $patchingStartTime
        lastBootTime = $lastBootTime
        rebootedAfterPatching = $rebootedAfterPatching
    }
    return $rebootStatus, $logData
}

function Test-PatchPresence{
    [cmdletbinding()]
    param(
        [string] $computerName,
        [object[]] $selectedPatches,
        [object] $psSession
    )
    $logData = New-Object System.Collections.ArrayList

    try{
        [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Querying Win32_QuickFixEngineering.")
        $installedPatches = Invoke-Command -Session $psSession -ScriptBlock {Get-CimInstance -ClassName Win32_QuickFixEngineering -OperationTimeoutSec 60 -ErrorAction Stop} -ErrorAction Stop
        [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Queried Win32_QuickFixEngineering.")
    }
    catch{
        [void]$logData.Add("$(Get-Timestamp) ERROR: $computerName - Failed to query Win32_QuickFixEngineering.")
        [void]$logData.Add($_.Exception.Message)

        $patchStatus = [PSCustomObject]@{
            patchQuerySuccessful = $false
            patchStatusOk = "unknown"
            missingPatches = "unknown"
        }
        return $patchStatus, $logData
    }

    $missingPatches = @(Compare-Object -ReferenceObject $installedPatches.hotfixId -DifferenceObject $selectedPatches -PassThru | Where-Object {$_.sideIndicator -eq "=>"}) # cast to array to facilitate report generation
    
    if(($missingPatches | Measure-Object).count -eq 0){
        $patchStatus = [PSCustomObject]@{
            patchQuerySuccessful = $true
            patchStatusOk = $true
            missingPatches = @($null) # cast to array to facilitate report generation
        }
    }
    else{
        $patchStatus = [PSCustomObject]@{
            patchQuerySuccessful = $true
            patchStatusOk = $false
            missingPatches = $missingPatches
        }
    }
    return $patchStatus, $logData
}

function Get-ServiceExclusionList{
    [cmdletBinding()]
    param(
        [object] $psSession,
        [string] $computerName,
        [string] $logFile
    )
    $logData = New-Object System.Collections.ArrayList
    $serviceConfigPath = "C:\osit\etc\srv_mon.cfg"

    $scriptBlock = {
        param(
            $serviceConfigPath,
            $computerName
        )
        # generate timestamp for logging
        function Get-TimeStamp {
            return Get-Date -f "yyyy-MM-dd HH:mm:ss -"
        }
        $logDataEntry = New-Object System.Collections.ArrayList

        try{
            [void]$logDataEntry.Add("$(Get-Timestamp) INFO: $computerName - Creating StreamReader to read srv_mon.cfg.")
            $streamReader = New-Object System.IO.StreamReader -ArgumentList $serviceConfigPath -ErrorAction Stop
            [void]$logDataEntry.Add("$(Get-Timestamp) INFO: $computerName - Created StreamReader to read srv_mon.cfg.")
        }
        catch{
            $serviceExclusionListObj = [PSCustomObject]@{
                serviceExclusionListQueryOk = $false
                serviceExclusionList = @($null)
            }
            [void]$logDataEntry.Add("$(Get-Timestamp) ERROR: $computerName - Failed to read srv_mon.cfg.")
            [void]$logDataEntry.Add($_.Exception.Message)

            return $serviceExclusionListObj, $logDataEntry
        }
        $line = $streamReader.ReadLine()

        while(($null -ne $line) -and (-not ($line -match '^AUTOMATIC_SERVICES_MONITORING_EXCEPTION_LIST'))){
            $line = $streamReader.ReadLine()
        }
        [void]$logDataEntry.Add("$(Get-Timestamp) INFO: $computerName - Finished reading srv_mon.cfg.")

        if($null -ne $line){
            $serviceExclusionList = ($line -match '".+"' | ForEach-Object -Process {$matches}).values.Split(',').Trim().Replace('"','')
            $serviceExclusionListObj = [PSCustomObject]@{
                serviceExclusionListQueryOk = $true
                serviceExclusionList = $serviceExclusionList
                }
            [void]$logDataEntry.Add("$(Get-Timestamp) INFO: $computerName - Found $(($serviceExclusionList | Measure-Object).count) services excluded from monitoring.")
            }
        else{
            $serviceExclusionListObj = [PSCustomObject]@{
                serviceExclusionListQueryOk = $false
                serviceExclusionList = @($null)
                }
            [void]$logDataEntry.Add("$(Get-Timestamp) INFO: $computerName - Found no services excluded from monitoring.")
            }
            return $serviceExclusionListObj, $logDataEntry
    }

    try{
        [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Querying osit service exclusion list.")
        $serviceExclusionListObj, $logDataEntry = Invoke-Command -Session $psSession -ScriptBlock $scriptBlock -ArgumentList $serviceConfigpath, $computerName -ErrorAction Stop
        [void]$logData.AddRange($logDataEntry)
        [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Queried osit service exclusion list.")
    }
    catch{
        [void]$logData.Add("$(Get-Timestamp) ERROR: $computerName - Failed to query osit service exclusion list. No exclusion list will be used for service status checks.")
        [void]$logData.Add($_.Exception.Message)
        return @($null), $logData
    }

    return $serviceExclusionListObj, $logData
}

function Test-RunningServices{
    [cmdletbinding()]
    param(
        [string] $computerName,
        [object] $psSession,
        [object] $serviceExclusionList,
        [string] $logFile
    )
    $logData = New-Object System.Collections.ArrayList

    try{
        # CIM query because Get-Service's underlying class doesn't contain StartType on older .NET versions (pre 4.6.1)
        [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Querying Win32_Service.")
        $allServices = Invoke-Command -Session $psSession -ScriptBlock {Get-CimInstance -ClassName Win32_Service -OperationTimeoutSec 60 -ErrorAction Stop} -ErrorAction Stop
        [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Queried Win32_Service.")
    }
    catch{
        [void]$logData.Add("$(Get-Timestamp) ERROR: $computerName - Failed to query Win32_Service.")
        [void]$logData.Add($_.Exception.Message)

        $serviceStatus = [PSCustomObject]@{
            serviceQuerySuccessful = $false
            serviceStatusOk = "unknown"
            failedServices = "unknown"
        }
        return $serviceStatus, $logData
    }
    $runningServices = $allServices | Where-Object {$_.State -eq "Running"}
    $automaticServices = $allServices | Where-Object {$_.StartMode -eq "Auto"}

    # find services with Automatic startup type but not in a running state
    $stoppedServices = Compare-Object -ReferenceObject $automaticServices -DifferenceObject $runningServices -PassThru | Where-Object {$_.sideIndicator -eq "<="}

    [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Checking stopped services against monitoring exclusion list.")

    # filter out services excluded in osit service monitoring config
    $stoppedServices = $stoppedServices | Where-Object {(Test-Match -inputString $_.displayName -regexPatternList $serviceExclusionList) -eq $false}

    # filter out services with start type Automatic/Delayed and Automatic/Trigger
    [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Checking stopped services' advanced startup type.")
    $stoppedServices = $stoppedServices | Where-Object {(Test-ServiceStartTypeAuto -serviceName $_.name -psSession $psSession) -eq $true}
    [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Checked stopped services' advanced startup type.")

    [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Found $(($stoppedServices | Measure-Object).count) stopped services not excluded by monitoring.")

    if($stoppedServices.Length -eq 0){
        $serviceStatus = [PSCustomObject]@{
            serviceQuerySuccessful = $true
            serviceStatusOk = $true
            failedServices = @($null)
        }
    }
    else{
        $serviceStatus = [PSCustomObject]@{
            serviceQuerySuccessful = $true
            serviceStatusOk = $false
            failedServices = $stoppedServices
        }
    }
    return $serviceStatus, $logData
}

function Test-PendingReboot{
    param(
        [object] $psSession
    )
    $logData = New-Object System.Collections.ArrayList

    $scriptBlock = {
        function Test-RegistryKey{
            param(
                [string] $registryKey
            )
            if(Get-Item -Path $registryKey -ErrorAction Ignore){
                return [PSCustomObject]@{
                    registryKey = $registryKey
                    pendingReboot = $true
                }
            }
            else{
                return [PSCustomObject]@{
                    registryKey = $registryKey
                    pendingReboot = $false
                }   
            }
        }

        function Test-RegistryValue{
            param(
                [string] $registryKey,
                [string] $registryValue
            )
            if(Get-ItemProperty -Path $registryKey -Name $registryValue -ErrorAction Ignore){
                return [PSCustomObject]@{
                    registryKey = $registryKey
                    registryValue = $registryValue
                    pendingReboot = $true
                }
            }
            else{
                return [PSCustomObject]@{
                    registryKey = $registryKey
                    registryValue = $registryValue
                    pendingReboot = $false
                }
            }
        }

        function Test-UpdateExeVolatile{
            $registryItemProperty = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Micrososft\Updates' -ErrorAction Ignore
            if($null -ne $registryItemProperty.updateExeVolatile -and $registryItemProperty.updateExeVolatile -ne 0){
                return [PSCustomObject]@{
                    registryKey = 'HKLM:\SOFTWARE\Microsoft\Updates'
                    registryValue = 'UpdateExeVolatile'
                    pendingReboot = $true
                }
            }
            else{
                return [PSCustomObject]@{
                    registryKey = 'HKLM:\SOFTWARE\Microsoft\Updates'
                    registryValue = 'UpdateExeVolatile'
                    pendingReboot = $false
                }
            }
        }

        function Test-WinUpdateServicesPending{
            if(Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\Pending' -ErrorAction Ignore){
                return [PSCustomObject]@{
                    registryKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\Pending'
                    pendingReboot = $true
                }
            }
            else{
                return [PSCustomObject]@{
                    registryKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\Pending'
                    pendingReboot = $false
                }
            }
        }

        function Start-PendingRebootChecks{
            $registryKeyList = @(
                #'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
                #'HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootInProgress',
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
                #'HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending',
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\PostRebootReporting'
                'HKLM:\SOFTWARE\Microsoft\ServerManager\CurrentRebootAttemps'
            )

            $pendingRebootObj = [PSCustomObject]@{
                pendingReboot = $false
            }

            # test existence of registry keys
            foreach($registryKey in $registryKeyList){
                $resultObj = Test-RegistryKey -RegistryKey $registryKey
                if($resultObj.pendingReboot -eq $true){
                    $pendingRebootObj = $resultObj
                    break
                }
            }
            
            if($pendingRebootObj.pendingReboot -eq $false){
                $resultObj = Test-UpdateExeVolatile
                if($resultObj.pendingReboot -eq $true){
                    $pendingRebootObj = $resultObj
                }
            }
            if($pendingRebootObj.pendingReboot -eq $false){
                $resultObj = Test-WinUpdateServicesPending
                if($resultObj.pendingReboot -eq $true){
                    $pendingRebootObj = $resultObj
                }
            }

            return $pendingRebootObj
        }
        $pendingRebootObj = Start-PendingRebootChecks
        return $pendingRebootObj
    }

    try{
        [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Performing pending reboot checks.")
        $pendingRebootObj = Invoke-Command -Session $psSession -ScriptBlock $scriptBlock -ErrorAction Stop
        [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Performed pending reboot checks.")
    }
    catch{
        [void]$logData.Add("$(Get-Timestamp) ERROR: $computerName - Failed to perform pending reboot checks.")
        [void]$logData.Add($_.Exception.Message)
    }
    
    return $pendingRebootObj, $logData
}
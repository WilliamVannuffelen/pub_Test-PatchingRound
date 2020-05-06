<#
.SYNOPSIS
Test-PatchingRound runs a number of checks on specified target systems to validate that the automated OS patching activities have succeeded.
.DESCRIPTION
The main script relies on the Test-PatchingRoundModule.psm1 module for its functions.
The script uses runspaces for a multithreaded approach to querying the target systems specified in the computerNamesFile parameter.

PS sessions are initialized to all specified target systems, and all subsequent queries make use of those to retrieve information from the target systems.

The following info is retrieved / checks are performed:
    - IP address
    - OS version
    - system type is physical or virtual
    - was a PS session initialized successfully
    - when was the system last rebooted
    - is the system pending reboot and if so: why
    - are all patches specified in the input file installed on the target system
    - are there any services in a stopped state that are of start type automatic and are not in the server's service monitoring exclusion list

.PARAMETER logFile
A string of the full path of the logFile to write to. 
Default: "$psScriptRoot\Test-PatchingRound_logs_$(Get-Date -Format yyyy-MM-dd).txt"
.PARAMETER patchingStartTime
A DateTime object to indicate when the patching round was started. Used to validate that system was rebooted after patching was started. Must be presented
as a properly formatted ISO 8601 compliant string: "yyyy-MM-dd HH:mm". E.g. "2020-03-29 16:17". Powershell handles the conversion to a DateTime object.
.PARAMETER patchesFile2012r2
A string of the full path of the plain text file containing a list of patches that should be installed on Windows Server 2012 R2 target systems. 
Default: "$psScriptRoot\patchesFile2012r2.txt"
.PARAMETER patchesFile2016
A string of the full path of the plain text file containing a list of patches that should be installed on Windows Server 2016 target systems. 
Default: "$psScriptRoot\patchesFile2016.txt"
.PARAMETER computerNamesFile
A string of the full path of the plain text file containing a list of computers to run the checks on.
Default: "$psScriptRoot\computerNamesFile.txt"
.PARAMETER domainCredentials
A PSCredential object containing the domain credentials the script will use to authenticate on domain-joined target systems.
.PARAMETER workgroupCredentials
A PSCredential object containing the credentials to be used for workgroup machines. This is an optional parameter and must be passed
.PARAMETER maxThreads
An integer which specifies how many runspaces will run concurrently. Can be increased for shorter runtime at the cost of increased resource requirements on the local server.
Default: 15
.PARAMETER reportFile
A string of the full path of the HTML report that will be generated.
Default: "$psScriptRoot\Test-PatchingRound_report_$(Get-Date -Format 'yyyy-MM-dd_HHmm').html"
.EXAMPLE
$credentials = Get-Credential
.\Test-PatchingRound.ps1 -patchingStartTime "2020-03-30 13:35" -patchesFile "C:\temp\patchesList.txt" -domainCredentials $credentials
#>
[CmdletBinding()]
param(
    [parameter(mandatory=$false)]
    [validateScript({
        if(Test-Path -Path (Split-Path $_ -Parent)){
            $true
        }
        else{
            throw "The parent directory of the specified logFile doesn't exist. Please provide a valid path."
        }
    })]
    [string] $logFile = "$($psScriptRoot)\Test-PatchingRound_logs_$(Get-Date -Format yyyy-MM-dd).txt",

    [parameter(mandatory=$true)]
    [dateTime] $patchingStartTime,

    [parameter(mandatory=$false)]
    [validateScript({
        if(Test-Path -Path $_ -PathType Leaf){
            $true
        }
        else{
            throw "The specified patchesFile2012r2 cannot be found. Please provide a valid path."
        }
    })]
    [string] $patchesFile2012r2 = "$($psScriptRoot)\patchesFile2012r2.txt",

    [parameter(mandatory=$false)]
    [validateScript({
        if(Test-Path -Path $_ -PathType Leaf){
            $true
        }
        else{
            throw "The specified patchesFile2016 cannot be found. Please provide a valid path."
        }
    })]
    [string] $patchesFile2016 = "$($psScriptRoot)\patchesFile2016.txt",

    [parameter(mandatory=$false)]
    [validateScript({
        if(Test-Path -Path $_ -PathType Leaf){
            $true
        }
        else{
            throw "The specified computerNamesFile cannot be found. Please provide a valid path."
        }
    })]
    [string] $computerNamesFile = "$($psScriptRoot)\computerNamesFile.txt",

    [parameter(mandatory=$true)]
    [psCredential] $domainCredentials,

    [parameter(mandatory=$false)]
    [psCredential] $workgroupCredentials = $null,

    [parameter(mandatory=$false)]
    [validateRange(1,25)]
    [int32] $maxThreads = 15,

    [parameter(mandatory=$false)]
    [validateScript({
        if(Test-Path (Split-Path $_ -Parent)){
            $true
        }
        else{
            throw "The parent directory of the specified reportFile doesn't exist. Please provide a valid path."
        }
    })]
    [string] $reportFile = "$($psScriptRoot)\Test-PatchingRound_report_$(Get-Date -Format 'yyyy-MM-dd_HHmm').html"
)

#----------------------------------------------------------
# FUNCTION DEFINITIONS
#----------------------------------------------------------

# generate timestamp for logging
function Get-TimeStamp {
    return Get-Date -f "yyyy-MM-dd HH:mm:ss -"
}

# test presence of custom module containing functions to be run on target systems
function Test-CustomModulePresent{
    try{
        Test-Path -Path "$psScriptRoot\Test-PatchingRoundModule.psm1" -PathType Leaf | Out-Null
        "$(Get-Timestamp) INFO: Test-PatchingRoundModule.psm1 is present on the system." | Tee-Object -FilePath $logFile -Append | Out-Host
    }
    catch{
        "$(Get-Timestamp) ERROR: Failed to find Test-PatchingRoundModule.psm1. Please ensure this file is present in the same location as Test-PatchingRound.ps1. The script will now terminate." | Tee-Object -FilePath $logFile -Append | Out-Host
        $_.Exception.Message | Tee-Object -FilePath $logFile -Append | Out-Host
        exit
    }
}

function Test-PatchesFileContent($patchesFile){
    try{
        $patchesList = Get-Content -Path $patchesFile -ErrorAction Stop
        "$(Get-Timestamp) INFO: Testing patchesFile content to ensure it is in the expected format." | Tee-Object -FilePath $logFile -Append | Out-Host
    }
    catch{
        "$(Get-Timestamp) ERROR: Failed to import patchesFile content. The script will now terminate." | Tee-Object -FilePath $logFile -Append | Out-Host
        $_.Exception.Message | Tee-Object -FilePath $logFile -Append | Out-Host
        exit
    }

    # ensure all patches are compliant with expected format
    $compliantPatches = $patchesList -match "KB\d{7}"
    if($compliantPatches.count -eq $patchesList.count){
        "$(Get-Timestamp) INFO: All provided patches match expected KB format." | Tee-Object -FilePath $logFile -Append | Out-Host
    }
    else{
        "$(Get-Timestamp) ERROR: Some or all provided patches don't match expected KB format. Please check the format of the input file. The script will now terminate." | Tee-Object -FilePath $logFile -Append | Out-Host
        exit
    }
    return $patchesList
}

function Test-ComputerNamesFileContent($computerNamesFile){
    try{
        $computerNamesList = Get-Content -Path $computerNamesFile -ErrorAction Stop
        "$(Get-Timestamp) INFO: Testing computerNamesFile content to ensure it is in the expected format." | Tee-Object -FilePath $logFile -Append | Out-Host
    }
    catch{
        "$(Get-Timestamp) ERROR: Failed to import computerNamesFile content. The script will now terminate." | Tee-Object -FilePath $logFile -Append | Out-Host
        $_.Exception.Message | Tee-Object -FilePath $logFile -Append | Out-Host
        exit
    }

    # ensure all computer names are compliant with expected format
    $compliantComputerNames = $computerNamesList -match "vpc-[a-z]{2}-(\d{3,6}\.)+redacted\.redacted\.redacted"

    if($compliantComputerNames.count -eq $computerNamesList.count){
        "$(Get-Timestamp) INFO: All provided computerNames match expected FQDN format." | Tee-Object -FilePath $logFile -Append | Out-Host
    }
    else{
        "$(Get-Timestamp) ERROR: Some or all provided computerNames don't match expected FQDN format. Please check the format of the input file. The script will now terminate." | Tee-Object -FilePath $logFile -Append | Out-Host
        exit
    }
    
    $domainComputerNamesList = @()
    foreach($computerName in $computerNamesList){
        $computerName = "$($computerName.Split('.')[0]).subdomain.domain.tld"
        $domainComputerNamesList += $computerName
    }

    return $domainComputerNamesList
}

# generate HTML report of consolidated query results
function New-HtmlReport{
    param(
        $results,
        $reportFile
    )
    "$(Get-Timestamp) INFO: Building HTML report of results." | Tee-Object -FilePath $logFile -Append | Out-Host
    # calculated properties to keep useful data and output in human-readable-friendly format
    $results = $results | 
        Select-Object   @{Name='computerName';          Expression={$_.computerName}},
                        @{Name='ipAddress';             Expression={$_.ipAddress}},
                        @{Name='osVersion';             Expression={$_.osVersion}},
                        @{Name='systemType';            Expression={$_.systemType}},
                        @{Name='psSessionOk';           Expression={$_.psSessionOk}},
                        @{Name='patchingStartTime';     Expression={$_.patchingStartTime.ToString('yyyy-MM-dd HH:mm:ss')}},
                        @{Name='lastRebootTime';        Expression={
                            switch($_.lastBootTime){
                                {$_ -is [dateTime]} {$_.ToString('yyyy-MM-dd HH:mm:ss')} # if query was successful, format to ISO 8601
                                {$_ -is [string]} {$_} # if query failed, just return 'unknown' string
                            }
                        }},
                        @{Name='rebootedAfterPatching'; Expression={$_.rebootedAfterPatching}},
                        @{Name='notPendingReboot';      Expression={
                            switch($_.pendingReboot){
                                {$_ -eq $true} {$false}
                                {$_ -eq $false} {$true}
                            }
                        }},
                        @{Name='pendingRebootReason';   Expression={$_.pendingRebootReason}},
                        @{Name='patchStatusOk';         Expression={$_.patchStatusOk}},
                        @{Name='missingPatches';        Expression={($_.missingPatches -join ', ')}}, # flatten array of missing patches for readability
                        @{Name='serviceExclusionListQueryOk';Expression={$_.serviceExclusionListQueryOk}},
                        @{Name='serviceStatusOk';   	Expression={$_.serviceStatusOk}},
                        @{Name='stoppedServices';       Expression={($_.failedServices.name -join ', ')}} # flatten array of failed service names for readability
    
    # HTML framework and CSS for report output
    $htmlParams = @{
        PostContent = "<p class='footer'>Generated on $(get-date -format 'yyyy-MM-dd HH:mm:ss')</p>"
        head = @"
 <Title>CONTOSO - Server patching validation - $(get-date -format 'yyyy-MM-dd')</Title>
<style>
body { background-color:#E5E4E2;
       font-family:Monospace;
       font-size:11pt; }
table { border-collapse: collapse;}
td, th { padding: 1px 1;
         border:1px solid black; 
         border-collapse:collapse;
         white-space:pre; }
th { font-weight: bold;
     color:white;
     background-color:black; }
table, tr, td, th { padding: 5px; margin: 0px ;white-space:pre; }
tr {
 border: solid;
 border-width: 3px 0;
 }
tr:nth-child(odd) {background-color: lightgray}
table { width:95%;margin-left:5px; margin-bottom:20px;}
h2 {
 font-family:Tahoma;
 color:#6D7B8D;
}
.error {
 background-color: red; 
 }
.success {
 color: green;
 }
.footer 
{ color:green; 
  margin-left:10px; 
  font-family:Tahoma;
  font-size:8pt;
  font-style:italic;
}
</style>
"@
    }

    # convert results array to HTML fragment, cast to XML to dynamically add HTML classes used by CSS
    [xml]$htmlData = $results | ConvertTo-Html -Fragment

    # loop over rows
    for($i=1; $i -le $htmlData.table.tr.count -1; $i++){
        # loop over columns
        for($y = 0; $y -le $htmlData.table.tr[$i].td.count -1; $y++){
            # if column value is $false or 'unknown', append error class for CSS
            if($htmlData.table.tr[$i].td[$y] -eq $false -or $htmlData.table.tr[$i].td[$y] -eq 'unknown'){
                $class = $htmlData.createAttribute("class")
                $class.value = 'error'
                [void]$htmlData.table.tr[$i].childNodes[$y].attributes.append($class)
            }
            # if column value is $true, append success class for CSS
            elseif($htmlData.table.tr[$i].td[$y] -eq $true){
                $class = $htmlData.createAttribute("class")
                $class.value = 'success'
                [void]$htmlData.table.tr[$i].childNodes[$y].attributes.append($class)
            }
        }
    }
    $htmlParams.add('body', $htmlData.innerXml)
    
    try{
        ConvertTo-Html @htmlParams | Out-File $reportFile -ErrorAction Stop
        "$(Get-Timestamp) INFO: Saved HTML report to $($reportFile)." | Tee-Object -FilePath $logFile -Append | Out-Host
    }
    catch{
        "$(Get-Timestamp) ERROR: Failed to save HTML report." | Tee-Object -FilePath $logFile -Append | Out-Host
        $_.Exception.Message | Tee-Object -FilePath $logFile -Append | Out-Host
    }
}

function Invoke-MainScript{
    [cmdletBinding()]
    param(
        $logFile,
        $patchingStartTime,
        $patchesList2012r2,
        $patchesList2016,
        $computerNamesList,
        $domainCredentials,
        $workgroupCredentials,
        $maxThreads
    )

    [void][RunspaceFactory]::CreateRunspacePool()
    $sessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $sessionState.ImportPSModule("$psScriptRoot\Test-PatchingRoundModule.psm1")

    $runspacePool = [RunspaceFactory]::CreateRunspacePool(
        1, # min threads
        $maxThreads, # max threads
        $sessionState,
        $host
    )

    $powershell = [Powershell]::Create()
    $powershell.runspacePool = $runspacePool
    $runspacePool.Open()

    $jobs = New-Object System.Collections.ArrayList

    foreach($computerName in $computerNamesList){
        $paramList = @{
            computerName = $computerName
            patchingStartTime = $patchingStartTime
            patchesList2012r2 = $patchesList2012r2
            patchesList2016 = $patchesList2016
            domainCredentials = $domainCredentials
            workgroupCredentials = $workgroupCredentials
            logFile = $logFile
        }

        $powershell = [Powershell]::Create()
        $powershell.runspacePool = $runspacePool
        [void]$powershell.AddScript({
            param(
                $computerName,
                $patchingStartTime,
                $patchesList2012r2,
                $patchesList2016,
                $domainCredentials,
                $workgroupCredentials,
                $logFile
            )

            $logData = New-Object System.Collections.ArrayList
            $runSpaceThreadId = [AppDomain]::GetCurrentThreadId()

            $startTime = Get-Date
            [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Starting checks.")

            [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Starting Get-ServerIpAddress.")
            $ipAddress, $logDataEntry = Get-ServerIpAddress -computerName $computerName
            [void]$logData.AddRange($logDataEntry)

            # launch PS session
            [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Starting Connect-PsSessionCustom.")
            $psSessionObject, $logDataEntry = Connect-PsSessionCustom -computerName $computerName -domainCredentials $domainCredentials -workgroupCredentials $workgroupCredentials
            $psSession = $psSessionObject.psSession
            [void]$logData.AddRange($logDataEntry)

            # if PS session was created, run checks
            if($psSession.GetType().name -eq 'psSession'){
                # check reboot after patching start
                [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Starting Test-RebootTime.")
                $rebootTime, $logDataEntry = Test-RebootTime -computerName $computerName -patchingStartTime $patchingStartTime -psSession $psSession
                [void]$logData.AddRange($logDataEntry)
                # check OS version
                $osVersion = $rebootTime.osVersion
                # check virtual or physical
                [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Starting Test-SystemType.")
                $systemType, $logDataEntry = Test-SystemType -psSession $psSession -computerName $computerName
                [void]$logData.AddRange($logDataEntry)
                # check for pending reboots
                [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Starting Test-PendingReboot.")
                $pendingRebootStatus, $logDataEntry = Test-PendingReboot -psSession $psSession
                [void]$logData.AddRange($logDataEntry)
                # check for presence of required patches
                if($osVersion -like "*2012*"){
                    [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Starting Test-PatchPresence.")
                    $patchStatus, $logDataEntry = Test-PatchPresence -computerName $computerName -selectedPatches $patchesList2012r2 -psSession $psSession
                }
                else{
                    [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Starting Test-PatchPresence.")
                    $patchStatus, $logDataEntry = Test-PatchPresence -computerName $computerName -selectedPatches $patchesList2016 -psSession $psSession
                }
                [void]$logData.AddRange($logDataEntry)
                # get service exclusion list from osit config
                [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Starting Get-ServiceExclusionList.")
                $serviceExclusionListObj, $logDataEntry = Get-ServiceExclusionList -psSession $psSession -computerName $computerName
                [void]$logData.AddRange($logDataEntry)
                # check all monitored auto start services are running
                [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Starting Test-RunningServices.")
                $serviceStatus, $logDataEntry = Test-RunningServices -computerName $computerName -psSession $psSession -serviceExclusionList $serviceExclusionListObj.serviceExclusionList
                [void]$logData.AddRange($logDataEntry)

                

                $combinedObj = [PSCustomObject]@{
                    runSpaceThreadId = $runSpaceThreadId
                    computerName = $computerName
                    osVersion = $osVersion
                    systemType = $systemType
                    ipAddress = $ipAddress
                    psSessionOk = $psSessionObject.psSessionOk
                    rebootQuerySuccessful = $rebootTime.rebootQuerySuccessful
                    patchingStartTime = $rebootTime.patchingStartTime
                    lastBootTime = $rebootTime.lastBootTime
                    rebootedAfterPatching = $rebootTime.rebootedAfterPatching
                    pendingReboot = $pendingRebootStatus.pendingReboot
                    pendingRebootReason = $pendingRebootStatus.registryKey
                    patchQuerySuccessful = $patchStatus.patchQuerySuccessful
                    patchStatusOk = $patchStatus.patchStatusOk
                    missingPatches = $patchStatus.missingPatches
                    serviceQuerySuccessful = $serviceStatus.serviceQuerySuccessful
                    serviceExclusionListQueryOk = $serviceExclusionListObj.serviceExclusionListQueryOk
                    serviceStatusOk = $serviceStatus.serviceStatusOk
                    failedServices = $serviceStatus.failedServices
                    logData = $logData
                }
                [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Removing PS Session.")
                Remove-PSSession -Id $psSession.id

                $endTime = Get-Date
                $timeDelta = $endTime - $startTime
                [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Checks took $($timeDelta.totalSeconds) seconds to complete.")
            }
            else{
                [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Unable to establish a PS session. All checks will be skipped.")
                $endTime = Get-Date
                $timeDelta = $endTime - $startTime
                [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Checks took $($timeDelta.totalSeconds) seconds to complete.")
                
                $combinedObj = [PSCustomObject]@{
                    runSpaceThreadId = $runSpaceThreadId
                    computerName = $computerName
                    osVersion = 'unknown'
                    systemType = 'unknown'
                    ipAddress = $ipAddress
                    psSessionOk = $psSessionObject.psSessionOk
                    rebootQuerySuccessful = $false
                    patchingStartTime = $patchingStartTime
                    lastBootTime = 'unknown'
                    rebootedAfterPatching = 'unknown'
                    pendingReboot = 'unknown'
                    pendingRebootReason = $null
                    patchQuerySuccessful = $false
                    patchStatusOk = 'unknown'
                    missingPatches = $null
                    serviceQuerySuccessful = $false
                    serviceExclusionListQueryOk = $false
                    serviceStatusOk = 'unknown'
                    failedServices = $null
                    logData = $logData
                }
            }
            [void]$logData.Add("$(Get-Timestamp) INFO: $computerName - Ended checks.")
            return $combinedObj
        })
        [void]$powershell.AddParameters($paramList)

        $handle = $powershell.BeginInvoke()

        $tempObject = [PSCustomObject]@{
            powershell = $powershell
            handle = $handle
        }
        [void]$jobs.Add($tempObject)
    }

    $results = $jobs | ForEach-Object{
        $_.powershell.EndInvoke($_.handle)
        $_.powershell.Dispose()
    }
    [void]$jobs.Clear()

    return $results
}

#---------------------------------------------------------- 
# FUNCTION CALLS
#----------------------------------------------------------
$startTime = Get-Date
"$(Get-Timestamp) INFO: Script started." | Tee-Object -FilePath $logFile -Append | Out-Host

Test-CustomModulePresent
$patchesList2012r2 = Test-PatchesFileContent $patchesFile2012r2
$patchesList2016 = Test-PatchesFileContent $patchesFile2016
$computerNamesList = Test-ComputerNamesFileContent $computerNamesFile

$mainScriptParams = @{
    logFile = $logFile
    patchingStartTime = $patchingStartTime
    patchesList2012r2 = $patchesList2012r2
    patchesList2016 = $patchesList2016
    computerNamesList = $computerNamesList
    domainCredentials = $domainCredentials
    workgroupCredentials = $workgroupCredentials
    maxThreads = $maxThreads
}
"$(Get-Timestamp) INFO: Starting checks on selected target systems. This may take a few minutes." | Tee-Object -FilePath $logFile -Append | Out-Host
$results = Invoke-MainScript @mainScriptParams
$results.logData | Out-File -FilePath $logFile -Append

New-HtmlReport -Results $results -ReportFile $reportFile

$endTime = Get-Date
$timeDelta = $endTime - $startTime
"$(Get-Timestamp) INFO: Script stopped. Total runtime: $($timeDelta.ToString('hh\h\ mm\m\ ss\s'))" | Tee-Object -FilePath $logFile -Append | Out-Host
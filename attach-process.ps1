<#
.PARAMETER service_name
    Service to restart (optional)
.PARAMETER process_name
    Process name to debug (required)
.PARAMETER commands
    String of windbg commands to be run at startup; separate more than one command with semi-colons (optional)
.EXAMPLE
    C:\PS> .\attach-process.ps1 -service-name fastbackserver -process-name fastbackserver -commands 'bp fastbackserver!recvfrom'

    Restart the fastback server service and then attach to the fastback server process. Addtionally, set a breakpoint as an initial command.
#>
[CmdletBinding()]
param (
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]
    $commands
)

DynamicParam {
    
    # Set the dynamic parameters' name
    $svc_param = 'service-name'
    
    # Create the dictionary 
    $RuntimeParameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

    # Create the collection of attributes
    $AttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
    
    # Create and set the parameters' attributes
    $ParameterAttribute = New-Object System.Management.Automation.ParameterAttribute

    # Add the attributes to the attributes collection
    $AttributeCollection.Add($ParameterAttribute)

    # Generate and set the ValidateSet 
    $svc_set = Get-Service | select -ExpandProperty Name
    $ValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($svc_set)

    # Add the ValidateSet to the attributes collection
    $AttributeCollection.Add($ValidateSetAttribute)

    # Create and return the dynamic parameter
    $RuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($svc_param, [string], $AttributeCollection)
    $RuntimeParameterDictionary.Add($svc_param, $RuntimeParameter)

    # repeat the process for the next dynamic param
    $ps_param = 'process-name'
    $ps_attrs = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
    $ps_paramattr = New-Object System.Management.Automation.ParameterAttribute
    $ps_attrs.Add($ps_paramattr)
    $ps_set = get-process | select -ExpandProperty Name
    $ps_validate = New-Object System.Management.Automation.ValidateSetAttribute($ps_set)
    $ps_attrs.add($ps_validate)
    $ps_rtp = New-Object System.Management.Automation.RuntimeDefinedParameter($ps_param, [string], $ps_attrs)
    $RuntimeParameterDictionary.add($ps_param, $ps_rtp)

    return $RuntimeParameterDictionary
}
begin {
    $service_name = $PsBoundParameters[$svc_param]

    if ($service_name) {
        $svc = get-service -name $service_name

        if ($svc.status -ne 'Running') {
            Write-Host "[+] Starting $service_name"
            start-service -name $service_name
        }        
    }

    $process_name = $PsBoundParameters[$ps_param]
}
process {
    $process = Get-Process $process_name
    
    $cmd_args = "-WF c:\windbg_custom.wew -g -p $($process.id)"
    
    if ($commands) {
        $cmd_args += " -c '$commands'"
    }
    
    write-host "[+] Attaching to $process_name"
    start-process -wait -filepath "C:\Program Files\Windows Kits\10\Debuggers\x86\windbg.exe" -verb RunAs -argumentlist $cmd_args

    if ($service_name) {
        Do {
            # restart the service once we detach from windbg
            restart-service -name $service_name -force -erroraction silentlycontinue 

            $svc = get-service -name $service_name 

            If ($svc.status -ne 'Running') { Write-Host "Waiting for service $service_name to start" ; Start-Sleep -Milliseconds 250 }
            Else { Write-Host "[+] $service_name has been restarted"}
    
        }
        Until ($svc.status -eq 'Running')
    }
}


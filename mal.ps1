﻿$SysmonPath = "C:\ProgramData\chocolatey\lib\sysinternals\tools\Sysmon64.exe"
$SysmonConfig =  "C:\Users\luke\desktop\FullLogging.xml"
$OutDirRoot = "C:\Users\luke\desktop\triage\"
$Execute = "C:\WINDOWS\System32\cmd.exe"
#$Execute = "C:\Program Files\Process Hacker 2\ProcessHacker.exe"
$executetime = 120

Function PrintMessage($Msg){
    $default = "$($Msg.UtcTime) - $($Msg.Type):"
    $PrintStrings = @{
        "Process Create"="`t$($Msg.ParentImage):$($Msg.ParentProcessId)  => $($Msg.Commandline)`n`tNew Process => $($Msg.Image):$($Msg.ProcessId)`n`tHash:$($Msg.Hashes)`n"
        "File created"="`t$($Msg.Image):$($Msg.ProcessId)`n`tCreated File:$($Msg.TargetFilename)`n"
        "Network connection detected"="`t$($Msg.Image):$($Msg.ProcessId)`n`t$($Msg.Protocol) $($Msg.SourceIp):$($Msg.SourcePort) => $($Msg.DestinationIp):$($Msg.DestinationPort) $($Msg.DestinationHostName)`n"
        "Dns query"="`t$($Msg.Image):$($Msg.ProcessId)`n`tQuery:$($Msg.QueryName) => Answer:$($Msg.QueryResults)`n"
        "Registry value set"="`t$($Msg.Image):$($Msg.ProcessId)`n`tKey:$($Msg.TargetObject) => $($Msg.Details)`n"
        "Pipe Created"="`t$($Msg.Image):$($Msg.ProcessId)`n`tPipeName:$($Msg.PipeName)`n"

    }
    if($PrintStrings.ContainsKey($Msg.Type)){
        Write-Host $default -ForegroundColor Green
        Write-Output $PrintStrings[$Msg.Type]
    }
    else{
        
        Write-Host $default -ForegroundColor Green
        Write-Output ($Msg | Out-String)
    }
}

Function pprint_events($events){
    #expects a list of eventlog objects, each event log object can have multiple events
    $events = $events | % { $_ | Select-Object | % { $_ | Select-Object} } | Sort-Object -Property TimeCreated
    $events | % { PrintMessage(get_obj_from_evt($_)) }
}

Function get_evts_by_keyword($term){
     $events = get-winevent -LogName "Microsoft-Windows-Sysmon/Operational" | Where-Object { $_.Message -match $term }
     return $events
}

Function get_evts_by_proc_id($id){
    $events = Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -FilterXPath ("*/*/Data[@Name='ProcessId']=$($id)") -ErrorAction SilentlyContinue
    return $events
}

Function get_child_evt_ids($id){
    $events = Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -FilterXPath ("*/*/Data[@Name='ParentProcessId']=$($id)") -ErrorAction SilentlyContinue
    $ids = $events | % { $_.Message | Select-String -Pattern "ProcessId: (\d+)" | % {($_.matches.groups[1]).value} } | Get-Unique
    return $ids
}

Function get_events($id){
    $events = @(get_evts_by_proc_id($id))

    $child_ids = get_child_evt_ids($id)
    if($child_ids.Count -gt 0){
        foreach($c_id in $child_ids){
           $events += get_events($c_id)
        }
    }
    return $events
}

Function get_obj_from_evt($evt){
    $messages = ($evt.Message).Split([Environment]::NewLine)
    $msg_obj = @()
    $msg_obj += "Type=$($messages[0] -replace ".$")"
    foreach($msg in $messages){
        if($msg -match '(^.*)(:\s)(.*)'){
            $msg_obj+=($msg -replace '(^.*)(:\s)(.*)','$1=$3')
        }
    }
    $msg_obj =($msg_obj -join [Environment]::NewLine) -replace '\\','\\' | ConvertFrom-StringData
    return $msg_obj
}

Function collect_files($events,$id){
    $fevents = $events | Where-Object { $_.Id -eq 11 }
    $hashes = @()
    foreach($event in $fevents){
        $event = get_obj_from_evt($event)
        if($event.UtcTime -eq $event.CreationUtcTime){
            if(Test-Path -Path $event.TargetFilename){
                $hash = (Get-FileHash -Algorithm MD5 $event.TargetFilename).Hash
                $hashes += $hash
                Copy-Item $event.TargetFilename -Destination "$($OutDir)files/$([System.IO.Path]::GetFilenameWithoutExtension($event.TargetFilename))_$($hash)"
            }else{
                Write-Host "File: $($event.TargetFIlename) missing, recover deleted file" -ForegroundColor
            }
        }
    }
    $hashes | Out-File "$($OutDir)hashes.txt"
}

$OutDir = "$($OutDirRoot)$($name)$($id)-$($date)/"
md -Force "$($OutDir)/files" > $null
Start-Transcript -OutputDirectory $OutDir

start-process -FilePath $SysmonPath -ArgumentList "-i $($SysmonConfig) -accepteula" -wait
(New-Object System.Diagnostics.Eventing.Reader.EventLogSession).ClearLog("Microsoft-Windows-Sysmon/Operational")

$date = $(get-date -f HH_mm_ss)
Write-Host "Executing: $Execute" -ForegroundColor Cyan
$proc = (Start-Process -FilePath $Execute -PassThru -Wait)
$id = $proc.Id
$name = $proc.Name
Write-host "$($name) with ProcessId: $($id)" -ForegroundColor Cyan

#Start-Sleep $executetime

$events = get_events($id)
pprint_events($events)
collect_files($events)

#Start-Process "C:\ProgramData\chocolatey\lib\sysinternals\tools\PsExec.exe"

while(1){
    $term = Read-Host -Prompt "Search logs for keyword, get process tree events with events(processid), or exit()"
    if($term -eq "exit()"){
        break
    }
    if($term -match "^events\(\d*\)"){
        $id = $term | Select-String -Pattern "^events\((\d+)\)" | % {($_.matches.groups[1]).value}
        get_events($id)
    }
    $events = get_evts_by_keyword($term)
    $events | format-list | write-output
}
#Stop-Process $proc.Id

start-process -FilePath $SysmonPath -ArgumentList "-u"
(New-Object System.Diagnostics.Eventing.Reader.EventLogSession).ClearLog("Microsoft-Windows-Sysmon/Operational")
Stop-Transcript
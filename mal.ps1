$SysmonPath = "C:\ProgramData\chocolatey\lib\sysinternals\tools\Sysmon64.exe"
$SysmonConfig =  "C:\Users\luke\desktop\triage\FullLogging.xml"
$OutDirRoot = "C:\Users\luke\desktop\triage\"
$DeletedPath = "C:\DeletedFiles\"
#$Execute = "C:\WINDOWS\System32\cmd.exe"
$Execute = "C:\Users\luke\desktop\rev.exe"
$executetime = 30

Function PrintMessage($Msg){
    $default = "$($Msg.UtcTime) - $($Msg.Type):"
    $PrintStrings = @{
        "Process Create"="`t$($Msg.ParentImage):$($Msg.ParentProcessId)  => $($Msg.Commandline)`n`tNew Process => $($Msg.Image):$($Msg.ProcessId)`n`tHash:$($Msg.Hashes)`n"
        "File created"="`t$($Msg.Image):$($Msg.ProcessId)`n`tCreated File:$($Msg.TargetFilename)`n"
        "File Delete"="`t$($Msg.Image):$($Msg.ProcessId)`n`tDeleted File:$($Msg.TargetFilename)`n`tHash:$($msg.Hashes)`n"
        "Network connection detected"="`t$($Msg.Image):$($Msg.ProcessId)`n`t$($Msg.Protocol) $($Msg.SourceIp):$($Msg.SourcePort) => $($Msg.DestinationIp):$($Msg.DestinationPort) $($Msg.DestinationHostName)`n"
        "Dns query"="`t$($Msg.Image):$($Msg.ProcessId)`n`tQuery:$($Msg.QueryName) => Answer:$($Msg.QueryResults)`n"
        "Registry value set"="`t$($Msg.Image):$($Msg.ProcessId)`n`tKey => $($Msg.TargetObject) => $($Msg.Details)`n"
        "Pipe Created"="`t$($Msg.Image):$($Msg.ProcessId)`n`tPipeName => $($Msg.PipeName)`n"
        "Pipe Connected"="`t$($Msg.Image):$($Msg.ProcessId)`n`tPipeName => $($Msg.PipeName)`n"
        "Process accessed"="`t$($Msg.SourceImage):$($Msg.SourceProcessId)`n`tAccessed ($($Msg.GrantedAccess)) => $($Msg.TargetImage):$($Msg.TargetProcessId)`n"
        "CreateRemoteThread detected"="`t$($Msg.SourceImage):$($Msg.SourceProcessId)`n`tCreated Thread => $($Msg.TargetImage):$($Msg.TargetProcessId) ThreadId => $($Msg.NewThreadId)`n"
    }
    if($PrintStrings.ContainsKey($Msg.Type)){
        if($Msg.Type -eq "CreateRemoteThread detected"){
            Write-Host $default -ForegroundColor Green
            Write-Host "Process injection likely." -ForegroundColor Red
            Write-Output $PrintStrings[$Msg.Type]
        }
        elseif($Msg.Type -eq "Process accessed"){
            $access = [int]($Msg.GrantedAccess)
            if($access -ge 0x1438 -and $access -lt 0x1fff){
                Write-Host $default -ForegroundColor Green
                Write-Host "Process injection likely." -ForegroundColor Red
                Write-Output $PrintStrings[$Msg.Type]
            }
        }
        else {
            Write-Host $default -ForegroundColor Green
            Write-Output $PrintStrings[$Msg.Type]
        }
    }
    else{
        Write-Host $default -ForegroundColor Green
        Write-Output ($Msg | Format-Table)
    }
}

Function pprint_events($events){
    #expects a list of eventlog objects, each event log object can have multiple events
    $events = $events | % { $_ | Select-Object | % { $_ | Select-Object} } | Sort-Object -Property TimeCreated
    $events | % { PrintMessage(get_obj_from_evt($_)) }
}

Function get_evts_by_keyword($term){
     $events = $all_events | Where-Object { $_.Message -match $term }
     return $events
}

Function get_evts_by_proc_id($id){
    $events = $all_events | Where-Object { $_.Message -match "`nProcessId:\s$($id)" -or $_.Message -match "SourceProcessId:\s$($id)" }
    return $events
}

Function get_child_evt_ids($id){
    $ids = @()
    #normal child events from process create
    $events = $all_events |  Where-Object { $_.Message -match "ParentProcessId:\s$($id)" }
    $ids += $events | % { $_.Message | Select-String -Pattern "ProcessId: (\d+)" | % {($_.matches.groups[1]).value} } | Sort-Object | Get-Unique
    
    #CreateRemoteThread child events
    $threads = $all_events |  Where-Object { $_.Message -match "CreateRemoteThread" -and $_.Message -match "SourceProcessId:\s$($id)" }
    $ids += $threads | % { $_.Message | Select-String -Pattern "TargetProcessId: (\d+)" | % {($_.matches.groups[1]).value} } | Sort-Object | Get-Unique
    
    #child process for likely injected processes based on mem access priviledges
	$memwritepriv = $all_events |  Where-Object { $_.Message -match "Process access" -and $_.Message -match "SourceProcessId:\s$($id)" }
    $memids = @()
    foreach($event in $memwritepriv){
        $access = $event.Message | Select-String -Pattern "GrantedAccess: (.*)" | % {($_.matches.groups[1]).value}
        if([int]$access -ge 0x1438 -and [int]$access -lt 0x1fff){
            $memids += $event.Message | Select-String -Pattern "TargetProcessId: (\d+)" | % {($_.matches.groups[1]).value}
            Write-Host -ForegroundColor Yellow "memids: "
            Write-Host -ForegroundColor Yellow $memids
        }
    }

    $ids = (($ids + $memids) | Sort-Object | Get-Unique)

    #TODO: process ids based on created services
    #TODO: process ids based on WMI events

    return $ids 
}

Function get_event_tree($id){
    $events = @(get_evts_by_proc_id($id))

    $child_ids = get_child_evt_ids($id)
    if($child_ids.Count -gt 0){
        foreach($c_id in $child_ids){
           $events += get_event_tree($c_id)
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
    if(Test-Path -Path "$($OutDir)hashes.txt"){
        $hashes = (Get-Content "$($OutDir)hashes.txt").split('`n')
    }else{
        $hashes = @()
    }
    $fevents = $events | Where-Object { $_.Id -eq 11 }

    foreach($event in $fevents){
        $event = get_obj_from_evt($event)
        if($event.UtcTime -eq $event.CreationUtcTime){
            if(Test-Path -Path $event.TargetFilename){
                $hash = (Get-FileHash -Algorithm SHA1 $event.TargetFilename).Hash
                $hashes += $hash
                Copy-Item $event.TargetFilename -Destination "$($OutDir)files/$([System.IO.Path]::GetFilename($event.TargetFilename))_$($hash)"
            }
        }
    }
    $fevents = $events | Where-Object { $_.Id -eq 23 }
    foreach($event in $fevents){
        $event = get_obj_from_evt($event)
        $hash = (($event.hashes).split("="))[1]
        $ext = [System.IO.Path]::GetExtension($event.TargetFilename)
        $path = "$($DeletedPath)$($hash)$($ext)"
        if(Test-Path -Path $path){
            $hashes += $hash
            Copy-Item $path -Destination "$($OutDir)files/deleted_$([System.IO.Path]::GetFilename($event.TargetFilename))_$($hash)"
        }
    }

    $hashes = $hashes | Sort-Object | Get-Unique
    if($hashes.Count -ge 1){
        $hashes | Out-File -Encoding ascii "$($OutDir)hashes.txt"
    }
}

md -Force "$($DeletedPath)" > $null
start-process -FilePath $SysmonPath -ArgumentList "-i $($SysmonConfig) -accepteula" -wait
(New-Object System.Diagnostics.Eventing.Reader.EventLogSession).ClearLog("Microsoft-Windows-Sysmon/Operational")

Write-Host "Executing: $Execute" -ForegroundColor Cyan

$proc = (Start-Process -FilePath $Execute -PassThru)
$id = $proc.Id
$name = $proc.Name

$date = $(get-date -f HH_mm_ss)

$OutDir = "$($OutDirRoot)$($name)_$($id)-$($date)/"
md -Force "$($OutDir)/files" > $null
Start-Transcript -OutputDirectory $OutDir
Write-host "$($name) with ProcessId: $($id)" -ForegroundColor Cyan

Start-Sleep $executetime

$global:all_events = Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational

$events = get_event_tree($id)
pprint_events($events)
collect_files($events)

while(1){
    $term = Read-Host -Prompt "Search logs for keyword, get process tree events with events(processid), or exit()"
    $all_events = Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational
    if($term -eq "exit()"){
        break
    }elseif($term -match "^events\(\d*\)"){
        $id = $term | Select-String -Pattern "^events\((\d+)\)" | % {($_.matches.groups[1]).value}
        $events = get_event_tree($id)
        pprint_events($events)
        collect_files($events)
    }else{
        $events = get_evts_by_keyword($term)
        $events | format-list | write-output
    }
}
Stop-Process $id

start-process -FilePath $SysmonPath -ArgumentList "-u"
(New-Object System.Diagnostics.Eventing.Reader.EventLogSession).ClearLog("Microsoft-Windows-Sysmon/Operational")
Stop-Transcript
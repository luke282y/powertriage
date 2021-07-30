#Optional Parameters to execute file passed into the script
param(
    [string]$cmd
)

#CONFIGURATION: Change these variables to meet your environment
$SysmonPath = "C:\powertriage\Sysmon64.exe"
$SysmonConfig =  "C:\powertriage\FullLogging.xml"
$OutDirRoot = "C:\powertriage\"
$DeletedPath = "C:\DeletedFiles\"

$etl2pcapng = "C:\powertriage\etl2pcapng.exe"
$capture_ip = "192.168.1.10"

$powershell = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$excel = "C:\Program Files\Microsoft Office\Office16\EXCEL.EXE"
$word = "C:\Program Files\Microsoft Office\Office16\WINWORD.EXE"
$cscript = "C:\Windows\System32\cscript.exe"

$executetime = 30
$Execute = "C:\WINDOWS\System32\cmd.exe"
#END CONFIGURATION

if($cmd){
    $Execute = $cmd
}

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
	"File Delete archived"="`t$($Msg.Image):$($Msg.ProcessId)`n`tDeleted File:$($Msg.TargetFilename)`n`tHash:$($msg.Hashes)`n"
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
    #process created files
    foreach($event in $fevents){
        $event = get_obj_from_evt($event)
        $timediff = New-TimeSpan -Start $event.UtcTime -End $event.CreationUtcTime
        if($timediff -le $executetime){
            if(Test-Path -Path $event.TargetFilename){
	    	try{
                	$hash = (Get-FileHash -Algorithm SHA1 $event.TargetFilename -ErrorAction SilentlyContinue).Hash
               		$hashes += $hash
                	Copy-Item $event.TargetFilename -Destination "$($OutDir)files\$([System.IO.Path]::GetFilename($event.TargetFilename))_$($hash)"
		}catch{
			 Write-Host -ForegroundColor Yellow "Can't Copy $($event.TargetFilename). File is open in another process.`nKill processes and try again? [Y] or [N]"
			 $term = Read-Host
			 if($term -match "^y"){
			 	kill_processes($events)
				Start-Sleep 2
				$hash = (Get-FileHash -Algorithm SHA1 $event.TargetFilename).Hash
               			$hashes += $hash
                		Copy-Item $event.TargetFilename -Destination "$($OutDir)files\$([System.IO.Path]::GetFilename($event.TargetFilename))_$($hash)"
			 }
		}
            }
        }
    }
    #process deleted files
    $fevents = $events | Where-Object { $_.Id -eq 23 }
    foreach($event in $fevents){
        $event = get_obj_from_evt($event)
        $hash = (($event.hashes).split("="))[1]
        $ext = [System.IO.Path]::GetExtension($event.TargetFilename)
        $path = "$($DeletedPath)$($hash)$($ext)"
        if(Test-Path -Path $path){
            $hashes += $hash
            Copy-Item $path -Destination "$($OutDir)files\deleted_$([System.IO.Path]::GetFilename($event.TargetFilename))_$($hash)"
        }
    }

    $hashes = $hashes | Sort-Object | Get-Unique
    if($hashes.Count -ge 1){
        $hashes | Out-File -Encoding ascii "$($OutDir)hashes.txt"
    }
}

Function network_capture_start(){
    Add-DnsClientNrptRule -Namespace ".arpa" -NameServers "127.0.0.1"
    $tracefile = "$($OutDir)trace.etl"
    New-NetEventSession -Name "maltrace" -LocalFilePath $tracefile > $null
    Add-NetEventProvider -Name "Microsoft-Windows-TCPIP" -SessionName "maltrace" > $null
    $proto = @(6,17)
    Add-NetEventPacketCaptureProvider -SessionName "maltrace" -EtherType 2048 -IpAddresses $capture_ip -IpProtocols $proto -TruncationLength 1500 > $null
    Start-NetEventSession -Name "maltrace" > $null
}

Function network_capture_stop($events){
    $tracefile = "$($OutDir)trace.etl"
    Stop-NetEventSession -Name "maltrace"
    Remove-NetEventSession
    start-process -FilePath "$($etl2pcapng)" -ArgumentList "`"$($tracefile)`" `"$($OutDir)trace.pcapng`""
    #TODO: filter pcap by detected nework events
}

Function start_execution($Execute){
    $extension = [System.IO.Path]::GetExtension($Execute)
    switch($extension){
        ".exe" {$proc = (Start-Process -FilePath $Execute -PassThru)}
        ".bat" {$proc = (Start-Process -FilePath $Execute -PassThru)}
	".xls" {$proc = (Start-Process -FilePath $excel -ArgumentList $Execute -PassThru)}
	".xlsx" {$proc = (Start-Process -FilePath $excel -ArgumentList $Execute -PassThru)}
	".xlsm" {$proc = (Start-Process -FilePath $excel -ArgumentList $Execute -PassThru)}
	".doc" {$proc = (Start-Process -FilePath $word -ArgumentList $Execute -PassThru)}
	".docx" {$proc = (Start-Process -FilePath $word -ArgumentList $Execute -PassThru)}
	".docm" {$proc = (Start-Process -FilePath $word -ArgumentList $Execute -PassThru)}
        ".ps1" {$proc = (Start-Process -FilePath $powershell -ArgumentList $Execute -PassThru)}
	".vbs" {$proc = (Start-Process -FilePath $cscript -ArgumentList $Execute -PassThru)}
	".js" {$proc = (Start-Process -FilePath $cscript -ArgumentList "//E:jscript $($Execute)" -PassThru)}
	".dll" {
	    $export = Read-Host -Prompt "File is a DLL, specify an export to execute or press enter to run DLL entry"
	    if([string]::IsNullOrEmpty($export)){
	        $proc = (Start-Process -FilePath "C:\WINDOWS\System32\rundll32.exe" -ArgumentList "$($Execute),#0" -PassThru)
	    } else {
	        $proc = (Start-Process -FilePath "C:\WINDOWS\System32\rundll32.exe" -ArgumentList "$($Execute),$($export)" -PassThru)
	    }
	}
        default {
            Write-Host "Unknown Extension: $($extension)" -ForegroundColor Yellow
            exit
        }
    }
    return $proc
}

Function cleanup(){
    #Clean up possible previous runs
    (New-Object System.Diagnostics.Eventing.Reader.EventLogSession).ClearLog("Microsoft-Windows-Sysmon/Operational")
    Stop-NetEventSession -Name "maltrace" -ErrorAction SilentlyContinue
    Remove-NetEventSession -ErrorAction SilentlyContinue
}

function kill_processes($events) {
    $ids = $events | % { $_.Message | Select-String -Pattern "ProcessId: (\d+)" | % {($_.matches.groups[1]).value} } | Sort-Object | Get-Unique
    foreach($id in $ids){
    	Stop-Process -Id $id -ErrorAction SilentlyContinue
	Wait-Process -Id $id -ErrorAction SilentlyContinue
    }
}

#Setup directories
md -Force "$($DeletedPath)" > $null
$date = $(get-date -f HH_mm_ss)
$name = [System.IO.Path]::GetFilename($Execute)
$OutDir = "$($OutDirRoot)$($name)-$($date)\"
md -Force "$($OutDir)\files" > $null
Write-Host "Ouput Directory: $($OutDir)`n" -ForegroundColor Cyan

Start-Transcript -OutputDirectory $OutDir

Write-Host "Starting Sysmon..." -ForegroundColor Cyan
start-process -FilePath $SysmonPath -ArgumentList "-i $($SysmonConfig) -accepteula" -wait

cleanup

Write-Host "Starting network capture...`n" -ForegroundColor Cyan
network_capture_start

Write-Host "Executing: $Execute" -ForegroundColor Cyan
$proc = start_execution($Execute)
$id = $proc.Id
$name = $proc.Name

Write-host "ProcessId: $($id)" -ForegroundColor Cyan

Write-Host "Monitoring system for: $($executetime) seconds`n" -ForegroundColor Cyan
Start-Sleep $executetime

Write-Host "Parsing events for process tree: $($id)...`n" -ForegroundColor Cyan

$global:all_events = Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -ErrorAction SilentlyContinue

$events = get_event_tree($id)

pprint_events($events)
collect_files($events)
network_capture_stop($events)
ii -path $OutDir

while(1){
    $term = Read-Host -Prompt "Search logs for keyword, get process tree events with events(processid), or exit()"
    $all_events = Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -ErrorAction SilentlyContinue
    if(!$term){
    	continue
    }elseif($term -eq "exit()"){
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

kill_processes($events)

start-process -FilePath $SysmonPath -ArgumentList "-u"
(New-Object System.Diagnostics.Eventing.Reader.EventLogSession).ClearLog("Microsoft-Windows-Sysmon/Operational")
Stop-Transcript

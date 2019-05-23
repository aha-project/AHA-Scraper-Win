param([uint32]$SecondsToScan=5)

Import-Module .\deps\Get-PESecurity\Get-PESecurity.psm1               #import the Get-PESecurity powershell module
. .\deps\Test-ProcessPrivilege\Test-ProcessPrivilege.ps1              #dot source the Get-PESecurity powershell module
$AHAScraperVersion='v0.8.6b6'						 #This script tested/requires powershell 2.0+, tested on Server 2008R2, Server 2016.

function GetNewPids
{
	Write-Host ('Scanning for new processes...')
	Get-Process | Sort-Object -Property Id | ForEach-Object {
		if (!$PIDToPath[([string]$_.Id)]) 
		{
			$ResultRecord=@{}
			$ResultRecord.PID=[string]$_.Id;
			$ResultRecord.ProcessName=$_.ProcessName+'.exe'
			$ResultRecord.ProcessPath=$_.Path
			$PIDToPath.Add( [string]$_.Id, $ResultRecord ) #basically all the other hashtables in here are indexed by string, make this consistent
			if ($ResultRecord.ProcessPath) { Get-BinaryScanForPID $ResultRecord.PID $ResultRecord.ProcessPath }
		}
	}
}

function GetNetConnections
{
	try { if ( Test-Path $NetConnectionsFile ) { Remove-Item $NetConnectionsFile } } #delete the old input csv file from last run, if exists, or we will end up with weird results (because this script will start reading while cports is writing over the old file)
	catch { Write-Warning -Message ('Unable to delete "{0}", there may be a permissions issue. Error: {1}' -f @($NetConnectionsFile,$Error[0])) }
	$MillisecondsToScan=$SecondsToScan*1000
	Write-Host ('Starting currports scan for {0} milliseconds...' -f @($MillisecondsToScan))
	.\deps\cports\cports.exe /cfg .\cports.cfg /scomma $NetConnectionsFile /CaptureTime $MillisecondsToScan /RunAsAdmin   #call cports and ask for a CSV. BTW if the .cfg file for cports is not present, this will break, because we need the CSV column headrs option set
}

function ScanNetconnections
{
	while($true)
	{
		Write-Host ('Waiting for currPorts to output csv file...')
		try 
		{ 
			if ( Test-Path $NetConnectionsFile ) { Get-Content $NetConnectionsFile -Wait -EA Stop | Select-String 'Process' | ForEach-Object { Write-Host ('NetConnections file generated.'); break } }
		} #attempt to read in a 1s loop until the file shows up
		catch { Write-Warning -Message( 'Unable to open input file. We will try again soon. Error:' -f @($Error[0])) }
		Start-Sleep 1 #sleep for 1s while we wait for file
	}
	Write-Host ('Finalizing NetConnections data...')
	$NetConnectionObjects=$(import-csv -path $NetConnectionsFile -delimiter ',')  #import the csv from currports

	foreach ($CSVLine in $NetConnectionObjects) #turn each line of the imported csv data into a hashtable, also clean up some input data at the same time
	{
		$ResultRecord=@{}
		$CSVLine | Get-Member -MemberType Properties | select-object -exp 'Name' | ForEach-Object {   #iterate over the columns, yes this open bracket has to be up here because powershell
			$Key=$_ -replace ' ',''                     #remove spaces from column names
			if ($Key -eq 'ProcessID') { $Key='PID' }    #change column name 'ProcessID' into 'PID'
			$Value=$($CSVLine | select-object -exp $_)         #get the value at the cell
			$ResultRecord[$Key]=$Value                  #insert into HT
		}
		$ResultRecord.ProductName=$ResultRecord.ProductName -replace '[^\p{L}\p{N}\p{Zs}\p{P}]', '' #remove annoying unicode registered trademark symbols
		$ResultRecord.FileDescription=$ResultRecord.FileDescription -replace '[^\p{L}\p{N}\p{Zs}\p{P}]', ''
		$ResultRecord.FileVersion=$ResultRecord.FileVersion -replace '[^\p{L}\p{N}\p{Zs}\p{P}]', ''
		$ResultRecord.Company=$ResultRecord.Company -replace '[^\p{L}\p{N}\p{Zs}\p{P}]', ''
		$ResultRecord.AHAScraperVersion=$AHAScraperVersion  #add the scraper version
		$ResultRecord.AHARuntimeEnvironment=$OurEnvInfo     #add the runtime info
		$ResultRecord.remove('WindowTitle')					#ignore useless column 'WindowTitle'
		$ProcessesByPid[$ResultRecord.PID]=$ResultRecord  #used for looking up an example of a process via a pid
		$WorkingData.Add($ResultRecord) | Out-Null #store this working data to the internal representation datastore
		if ($ResultRecord.ProcessPath) { Get-BinaryScanForPID $ResultRecord.PID $ResultRecord.ProcessPath }
	}
}

function GetHandles
{
	$HandleFile='handles.output'
	if ( !(Test-Path $HandleEXEPath) )  { Write-Host ('User has not installed "Handle" from SysInternals suite to {0}, or EULA not accepted (launch once by double clicking), skipping.' -f @($HandleEXEPath)); return }
	Write-Host ('Scanning for new pipes...')
	try { if ( Test-Path $HandleFile ) { Remove-Item $HandleFile } } #empty out the old output csv file from last run if exists, to ensure fresh result regardless of any bugs later in the script
	catch { Write-Warning ('Unable to clear out "{0}", there may be a permissions issue. Error: {1}' -f @($HandleFile,$Error[0])) }
	& $HandleEXEPath -a > $HandleFile 

	while($true) #unlikely we need this anymore but leave here to test
	{
		try 
		{ 
			if ( Test-Path $HandleFile ) { Get-Content $HandleFile -Wait -EA Stop | Select-String 'Process' | ForEach-Object { break } }
		} #attempt to read in a 1s loop until the file shows up
		catch { Write-Warning -Message ('Unable to open input file. We will try again soon. Error:' -f @($Error[0])) }
		Write-Host ('Waiting for handle to output file...')
		Start-Sleep 1 #sleep for 1s while we wait for file
	}
	$HandleObjects=$(Get-Content -path $HandleFile )  #import the csv from currports
	$CurrentExecutable='' #executable is updated everytime an interation of the loop sees an exe, so this needs to persist between iterations
	foreach ($HandleLine in $HandleObjects) #turn each line of the imported data into a hashtable
	{
		$HandleLine=$HandleLine.Trim()
		if ( $HandleLine -lt 4) { continue; }
		if ( $HandleLine -like '* pid: *' ) { $CurrentExecutable=$HandleLine; }
		if ( $HandleLine -like '*\Device\NamedPipe\*' ) 
		{ 
			$PipePathTokens=$HandleLine -split '\\Device\\NamedPipe\\'
			$PipePath=$PipePathTokens[1]
			$CurProcTokens=$CurrentExecutable.split()
			if (!$CurProcTokens[0] -or !$CurProcTokens[2] -or !$PipePath) { continue; }
			$HandlePID=$CurProcTokens[2];
			$PartialResult=@{}
			$PartialResult.PID=$HandlePID
			$PartialResult.PipePath=$PipePath

			$Found=$false
			foreach ( $tempInfo in $PartialPipeResults )
			{
				if ($tempInfo.PID -eq $PartialResult.PID -and $tempInfo.PipePath -eq $PartialResult.PipePath )
				{
					$Found=$true
					break
				}
			}
			if (!$Found) { $PartialPipeResults.add( $PartialResult ) | Out-Null }

			$PidAsNum=$HandlePID -as [int]
			if ($PipeToPidMap[$PipePath])
			{
				if ($PipeToPidMap[$PipePath[1]] -gt $PidAsNum) { $PipeToPidMap[$PipePath]=$PidAsNum }
			}
			else { $PipeToPidMap[$PipePath]=$PidAsNum }
		}
	}
	try { if ( Test-Path $HandleFile ) { Remove-Item $HandleFile } } #empty out the old output csv file from last run if exists, to ensure fresh result regardless of any bugs later in the script
	catch { Write-Warning ('Unable to clear out "{0}", there may be a permissions issue. Error: {1}' -f @($HandleFile,$Error[0])) }
}

function ScanHandles
{
	Write-Host ('Finalizing handle data...')
	foreach ($HandleLine in $PartialPipeResults) #turn each line of the imported data into a hashtable
	{
		$HandlePID=$HandleLine.PID
		$PipePath=$HandleLine.PipePath
		$ResultRecord=@{}

		if ($ProcessesByPid[$HandlePID]) #we have seen this pid before
		{
			$PidProcess=$ProcessesByPid[$HandlePID]
			$PidProcess.Keys | ForEach-Object { $ResultRecord[$_]=$PidProcess[$_] }
			$ResultRecord.LocalPort=''
			$ResultRecord.RemotePort=''
			$ResultRecord.RemoteHostName=''
			$ResultRecord.State=''
			$ResultRecord.LocalAddress=''
			$ResultRecord.RemoteAddress=''
		}
		else 
		{ # Write-Host ('Found a pipe only proc {0}' -f @($HandlePID))
			$BlankHandleResult.Keys | ForEach-Object { $ResultRecord[$_]=$BlankHandleResult[$_] }
			$ResultRecord.PID=$HandlePID
			$PidRecord=$PIDToPath[$ResultRecord.PID]
			if (!$PidRecord) { Write-Warning -Message ('failed to locate a pid record for pid {0}' -f @($HandlePID)) }
			$ResultRecord.ProcessPath=$PidRecord.ProcessPath
			$ResultRecord.ProcessName=$PidRecord.ProcessName
			if (!$($PidRecord.ProcessPath)) { Write-Warning -Message ('No path info for {0} {1}' -f @($HandlePID,$PidRecord.ProcessName)) }
		}
		
		if (!$UniquePipeNumber[$PipePath]) { $UniquePipeNumber[$PipePath]=$PipeCounter++ }
		$ResultRecord.Protocol='pipe'
		$ResultRecord.State='Established'
		$ResultRecord.LocalAddress=$PipePath
		$ResultRecord.RemoteAddress=$PipePath
		$ResultRecord.LocalPort=$UniquePipeNumber[$PipePath]
		$ResultRecord.RemotePort=$UniquePipeNumber[$PipePath]
		$ResultRecord.AHAScraperVersion=$AHAScraperVersion  #add the scraper version
		$ResultRecord.AHARuntimeEnvironment=$OurEnvInfo     #add the runtime info
	
		if (!$ProcessesByPid[$ResultRecord.PID]) { $ProcessesByPid[$ResultRecord.PID]=$ResultRecord } #used for looking up an example of a process via a pid (if one exists, ignore, since there will be more info in an example from cports)

		$LowestPipePid=[string] $PipeToPidMap[$PipePath]
		if ($ResultRecord.PID -eq $LowestPipePid) { $ResultRecord.State='Listening' }
		if (!$Found) { $WorkingData.Add($ResultRecord) | Out-Null } #store this working data to the internal representation datastore
		
	}
}

function Get-BinaryScanForPID
{
	param([string]$ProcessID, [string]$EXEPath)
	try
    {	if ( ($ProcessID -eq 0) -and (!$EXEPath) ) { return }  #skip if there's no path to exe defined and we're process zero, to hide _only_ the expected failure, others we should print about
		if ( $BinaryScanResultsByPID[$ProcessID] ) { return }    #if we already have a result for this process id, then no need to scan anything
		$FileResults=@{}
		$EXEResults=$BinaryScanResultsByPath[$EXEPath];
		if (!$EXEResults) 
		{
			$EXEResults=@{}
			$BinaryScanError.Keys | ForEach-Object { $EXEResults[$_]=$BinaryScanError[$_] } #fill in placeholder values to fill in all known fields with 'ScanError' in case they are not populated by any of the scans
			$FileToHash=$null
			try { $FileToHash=[System.IO.File]::OpenRead($EXEPath) } #open file so we can hash the data
			catch { Write-Warning -Message ('Unable to open file "{0}" for scanning.' -f @($EXEPath)) }
			if ($FileToHash)  #if we couldn't open the file there's no point in attempting the following
			{
				Write-Host ('Scanning ProcessID={0} "{1}"...' -f @($ProcessID,$EXEPath))
				$EXEResults.SumSHA512=[System.BitConverter]::ToString($($SHA512Alg.ComputeHash($FileToHash))).Replace('-', [String]::Empty).ToLower(); $FileToHash.Position=0; #compute the sha512 hash, rewind stream
				$EXEResults.SumSHA256=[System.BitConverter]::ToString($($SHA256Alg.ComputeHash($FileToHash))).Replace('-', [String]::Empty).ToLower(); $FileToHash.Position=0; #compute the sha256 hash, rewind stream
				$EXEResults.SumSHA1  =[System.BitConverter]::ToString(  $($SHA1Alg.ComputeHash($FileToHash))).Replace('-', [String]::Empty).ToLower(); $FileToHash.Position=0; #compute the sha1   hash, rewind stream
				$EXEResults.SumMD5   =[System.BitConverter]::ToString(   $($MD5Alg.ComputeHash($FileToHash))).Replace('-', [String]::Empty).ToLower();                         #compute the md5    hash
				$FileToHash.Dispose();
				$FileToHash.Close();
				try 
				{	#This scan will populate 'ARCH', 'ASLR', 'DEP', 'Authenticode', 'StrongNaming', 'SafeSEH', 'ControlFlowGuard', 'HighEntropyVA', 'DotNET'
					$Temp=Get-PESecurity -File $EXEPath -EA SilentlyContinue
					$Temp | Get-Member -MemberType Properties | ForEach-Object { $EXEResults[$_.Name]=$Temp[$_.Name] } #copy over what we got from PESecurity
				}
				catch { Write-Warning -Message ('PESecurity: Unable to scan file. Error: {0}' -f @($Error[0])) }
				$EXEResults.remove('FileName')  #remove unnecessary result from Get-PESecurity
				$BinaryScanResultsByPath[$EXEPath]=$EXEResults
			}
		}
		$EXEResults.Keys | ForEach-Object { $FileResults[$_]=$EXEResults[$_] }
		try
			{	#This scan will populate 'PrivilegeLevel','Privileges' in the final output file
				$PrivilegeInfo = Test-ProcessPrivilege -processId $ProcessID -EA SilentlyContinue
				$FileResults.PrivilegeLevel = $PrivilegeInfo.PrivilegeLevel
				$FileResults.Privileges = $PrivilegeInfo.Privileges
			}
			catch { Write-Warning ('Test-ProcessPrivilege: Unable to check PID={0}. Error: {1}' -f @($ProcessID,$Error[0])) }
		$BinaryScanResultsByPID[$ProcessID]=$FileResults  #insert results from scanning this binary into the dataset of scanned binaries
    }
	catch { Write-Warning ('Unexpected overall failure scanning "{0}" line: {1} Error: {2}' -f @($EXEPath,$Error[0].InvocationInfo.ScriptLineNumber, $Error[0])) }
}

function Write-Output
{
	Write-Host ('Writing results...')
	foreach ($ResultRecord in $WorkingData)
	{
		try
		{
			$ScanResult=$null;
			if ($($ResultRecord.PID)) { $ScanResult=$($BinaryScanResultsByPID[$($ResultRecord.PID)]) }   #try to grab the correct result from dataset of scanned binaries
			if (!$ScanResult) { $ScanResult=$BinaryScanError }                              #if we cant find a result for this EXEPath, we'll use the default set of errors
			$ScanResult.Keys | ForEach-Object { $ResultRecord[$_]=$ScanResult[$_] }                      #copy the results for the binary into this line of the output
		}
		catch { Write-Warning -Message ('Error at line: {0} Error: {1}' -f @($Error[0].InvocationInfo.ScriptLineNumber, $Error[0])) }
		$OutputData.Add((New-Object PSObject -Property $ResultRecord)) | Out-Null # TODO:I don't recall entirely why we have to make it a PSObject for export-csv to like it...something to look into in the future I suppose
	}

	$TempCols=@{}
	$SortedColumns=@('ProcessName','PID','ProcessPath','Protocol','LocalAddress','LocalPort','RemoteAddress','RemotePort','RemoteHostName','State') #this is the list of columns (in order) that we want the output file to start with
	$OutputData[0] | Get-Member -MemberType Properties | Select-Object -exp 'Name' | ForEach-Object { $TempCols[$_]=$_ } #copy column names from line 0 of the output data into a new hash table so we can work on formatting
	$SortedColumns | ForEach-Object { $TempCols.remove($_) } 	   #remove the set of known colums we want the file to start with from the set of all possible columns
	$BinaryScanError.Keys | ForEach-Object { $TempCols.remove($_) } #remove all the binary/exe security scan columns, from the set of all possible columns, so we can add them in at the end after the sort of the other columns
	$TempCols.GetEnumerator() | Sort-Object -Property name | ForEach-Object { $SortedColumns+=$($_.key).ToString() } #sort and dump the rest into (what will be the middle of) the array
	$BinaryScanError.remove('PrivilegeLevel')      #remove these two because they look better next to the columns above than mixed in with the other security scan info
	$BinaryScanError.remove('Privileges')
	$SortedColumns+='PrivilegeLevel'               #add to list of output columns here before we add the binary scan columns
	$SortedColumns+='Privileges'
	$BinaryScanError.GetEnumerator() | Sort-Object -Property name | ForEach-Object { $SortedColumns+=$($_.key).ToString() } #sort and then add in the binary/exe security scan columns at the end of the sorted set of columns

	#TODO: future: sort output rows by pid?
	$OutputData | Select-Object $SortedColumns | Export-csv $BinaryAnalysisFile -NoTypeInformation -Encoding UTF8 # write all the results to file
}



#Entry point into script is here (everything above should be function or param definitions)

$NetConnectionsFile='.\NetConnections.csv'         
$BinaryAnalysisFile='.\BinaryAnalysis.csv'

$SHA512Alg=new-object -type System.Security.Cryptography.SHA512Managed                 #Algorithms for doing various file hash operations
$SHA256Alg=new-object -type System.Security.Cryptography.SHA256Managed
$SHA1Alg  =new-object -type System.Security.Cryptography.SHA1Managed
$MD5Alg   =new-object -type System.Security.Cryptography.MD5CryptoServiceProvider

$BinaryScanError=@{ 'ARCH'='ScanError';'ASLR'='ScanError';'DEP'='ScanError';'Authenticode'='ScanError';'StrongNaming'='ScanError';'SafeSEH'='ScanError';'ControlFlowGuard'='ScanError';'HighentropyVA'='ScanError';'DotNET'='ScanError';'SumSHA512'='ScanError';'SumSHA256'='ScanError';'SumSHA1'='ScanError';'SumMD5'='ScanError';'PrivilegeLevel'='ScanError';'Privileges'='ScanError' }
$BlankHandleResult=@{ 'ProcessName'='';'PID'='';'Protocol'='';'LocalPort'='';'LocalPortName'='';'LocalAddress'='';'RemotePort'='';'RemotePortName'='';'RemoteAddress'='';'RemoteHostName'='';'State'='';'SentBytes'='';'ReceivedBytes'='';'SentPackets'='';'ReceivedPackets'='';'ProcessPath'='';'ProductName'='';'FileDescription'='';'FileVersion'='';'Company'='';'ProcessCreatedOn'='';'UserName'='';'ProcessServices'='';'ProcessAttributes'='';'AddedOn'='';'CreationTimestamp'='';'ModuleFilename'='';'RemoteIPCountry'=''; }
$PipeCounter=[int]1; #shared counter so we can assign a unique number to each pipe
[System.Collections.ArrayList]$WorkingData=New-Object System.Collections.ArrayList($null) #create empty array list for our working dataset
[System.Collections.ArrayList]$PartialPipeResults=New-Object System.Collections.ArrayList($null) #create empty array list for our working dataset
[System.Collections.ArrayList]$OutputData=New-Object System.Collections.ArrayList($null)  #create empty array list for final output dataset

#lookup tables
$PIDToPath=@{}
$BinaryScanResultsByPID=@{}   #Binary scan results by PID
$BinaryScanResultsByPath=@{}  #Binary scan results by path of exe
$ProcessesByPid=@{}
$PipeToPidMap=@{}
$UniquePipeNumber=@{}

try { if ( Test-Path $BinaryAnalysisFile ) { Clear-Content $BinaryAnalysisFile } } #empty out the old output csv file from last run if exists, to ensure fresh result regardless of any bugs later in the script
catch { Write-Warning ('Unable to clear out "{0}", there may be a permissions issue. Error: {1}' -f @($BinaryAnalysisFile,$Error[0])) }


$TempInfo=(Get-WmiObject win32_operatingsystem)
$OurEnvInfo='PowerShell {0} on {1} {2}' -f @($PSVersionTable.PSVersion.ToString().trim(),$TempInfo.caption.toString().trim(),$TempInfo.OSArchitecture.ToString().trim())
Write-Host ('AHA-Scraper {0} starting in {1}' -f @($AHAScraperVersion,$OurEnvInfo))
$HandleEXEPath='.\deps\handle\handle.exe'
if ( $TempInfo.OSArchitecture.ToString().trim() -like '*64*' ) { Write-host ('64-bit machine detected, will attempt to use handle64.exe for pipe scans.');$HandleEXEPath='.\deps\handle\handle64.exe' }


GetNetConnections
$totalScanTime=[Diagnostics.Stopwatch]::StartNew()

while ($true)
{
	GetHandles
	GetNewPids
	$Elapsed=$totalScanTime.Elapsed.TotalSeconds -as [uint32]
	if  ( $Elapsed -gt $SecondsToScan ) {break;}
	Write-Host ('Continuing subscans, {0} seconds have elapsed of time budget {1} seconds' -f @($Elapsed,$SecondsToScan))
}

Write-Host ('Scan over time complete, finalizing results.')
ScanNetconnections
ScanHandles #always finalize handles after netconnections, since netconenctions will populate more pid fields we can use

Write-Output

$totalScanTime.Stop()
Write-Host ('Complete, elapsed time: {0}.' -f @($totalScanTime.Elapsed)) #report how long it took to scan/process everything


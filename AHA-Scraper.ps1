$AHAScraperVersion='v0.8.5b16'						 #This script tested/requires powershell 2.0+, tested on Server 2008R2, Server 2016.
$NetConnectionsFile='.\NetConnections.csv'           
$BinaryAnalysisFile='.\BinaryAnalysis.csv'

Import-Module .\deps\Get-PESecurity\Get-PESecurity.psm1               #import the Get-PESecurity powershell module
. .\deps\Test-ProcessPrivilege\Test-ProcessPrivilege.ps1              #dot source the Get-PESecurity powershell module

try { if ( Test-Path $NetConnectionsFile ) { Remove-Item $NetConnectionsFile } } #delete the old input csv file from last run, if exists, or we will end up with weird results (because this script will start reading while cports is writing over the old file)
catch { Write-Warning 'Unable to delete "{0}", there may be a permissions issue. Error: {1}' -f @($NetConnectionsFile,$Error[0])}
try { if ( Test-Path $BinaryAnalysisFile ) { Clear-Content $BinaryAnalysisFile } } #empty out the old output csv file from last run if exists, to ensure fresh result regardless of any bugs later in the script
catch { Write-Warning 'Unable to clear out "{0}", there may be a permissions issue. Error: {1}' -f @($BinaryAnalysisFile,$Error[0])}

$TempInfo=(Get-WmiObject win32_operatingsystem)
$OurEnvInfo='PowerShell {0} on {1} {2}' -f @($PSVersionTable.PSVersion.ToString().trim(),$TempInfo.caption.toString().trim(),$TempInfo.OSArchitecture.ToString().trim())
Write-Host ('AHA-Scraper {0} starting in {1}' -f @($AHAScraperVersion,$OurEnvInfo))

.\deps\cports\cports.exe /cfg .\cports.cfg /scomma $NetConnectionsFile    #call cports and ask for a CSV. BTW if the .cfg file for cports is not present, this will break, because we need the CSV column headrs option set
while($true)
{
	Write-Host ('Waiting for currPorts to output csv file...')
	try 
	{ 
		if ( Test-Path $NetConnectionsFile ) { Get-Content $NetConnectionsFile -Wait -EA Stop | Select-String 'Process' | %{ Write-Host 'NetConnections file generated.'; break } }
	} #attempt to read in a 1s loop until the file shows up
    catch { Write-Warning ( 'Unable to open input file. Probably fine, we will try again soon. Error:' -f @($Error[0])) }
    Start-Sleep 1 #sleep for 1s while we wait for file
}
Start-Sleep 1 #sleep for one more second to ensure the file is fully written/consistent on disk (which it should be, since cports has already exited, this is hopefully unnecessary, but seemed like a good idea.

$totalScanTime=[Diagnostics.Stopwatch]::StartNew()
Write-Host ('Importing "{0}"...' -f @($NetConnectionsFile))
$NetConnectionObjects=$(import-csv -path $NetConnectionsFile -delimiter ',')  #import the csv from currports
[System.Collections.ArrayList]$WorkingData=New-Object System.Collections.ArrayList($null) #create empty array list for our working dataset
[System.Collections.ArrayList]$OutputData=New-Object System.Collections.ArrayList($null)  #create empty array list for final output dataset
$ProcessesByPid=@{}

foreach ($CSVLine in $NetConnectionObjects) #turn each line of the imported csv data into a hashtable, also clean up some input data at the same time
{
    $ResultRecord=@{}
	$CSVLine | Get-Member -MemberType Properties | SELECT -exp 'Name' | % {   #iterate over the columns, yes this open bracket has to be up here because powershell
		$Key=$_ -replace ' ',''                     #remove spaces from column names
		if ($Key -eq 'ProcessID') { $Key='PID' }    #change column name 'ProcessID' into 'PID'
		$Value=$($CSVLine | SELECT -exp $_)         #get the value at the cell
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
}

$SHA512Alg=new-object -type System.Security.Cryptography.SHA512Managed                 #Algorithms for doing various file hash operations
$SHA256Alg=new-object -type System.Security.Cryptography.SHA256Managed
$SHA1Alg  =new-object -type System.Security.Cryptography.SHA1Managed
$MD5Alg   =new-object -type System.Security.Cryptography.MD5CryptoServiceProvider
$BinaryScanError=@{ 'ARCH'='ScanError';'ASLR'='ScanError';'DEP'='ScanError';'Authenticode'='ScanError';'StrongNaming'='ScanError';'SafeSEH'='ScanError';'ControlFlowGuard'='ScanError';'HighentropyVA'='ScanError';'DotNET'='ScanError';'SumSHA512'='ScanError';'SumSHA256'='ScanError';'SumSHA1'='ScanError';'SumMD5'='ScanError';'PrivilegeLevel'='ScanError';'Privileges'='ScanError' }

Write-Host 'CSV File imported. Scanning detected binaries:'
$BinaryScanResults=@{} #overall result set produced from scanning all unique deduplicated binaries found in $NetConnectionObjects
ForEach ( $ProcessToScan in $ProcessesByPid.values ) #use the PID as the uniqe-ifier here since a single .exe can be launcehd by multiple users
{
	$EXEPath=$ProcessToScan.ProcessPath #$EXEInfo.'Process Path' #get the actual path 
	$ProcessID=$ProcessToScan.PID #$EXEInfo.'Process ID'
	try
    {	if ( ($ProcessID -eq 0) -and (!$EXEPath) ) { continue }      #skip if there's no path to exe defined and we're process zero, to hide _only_ the expected failure, others we should print about
		Write-Host ('Scanning ProcessID={0} "{1}"...' -f @($ProcessID,$EXEPath))
		$FileResults=@{}
		$BinaryScanError.Keys | % { $FileResults[$_]=$BinaryScanError[$_] } #fill in placeholder values to fill in all known fields with 'ScanError' in case they are not populated by any of the scans
		$FileToHash=$null
		try { $FileToHash=[System.IO.File]::OpenRead($EXEPath) } #open file so we can hash the data
		catch { Write-Warning -Message ( 'Unable to open file "{0}" for scanning.' -f @($EXEPath)) }
		if ($FileToHash)  #if we couldn't open the file there's no point in attempting the following
		{
			$FileResults.SumSHA512=[System.BitConverter]::ToString($($SHA512Alg.ComputeHash($FileToHash))).Replace('-', [String]::Empty).ToLower(); $FileToHash.Position=0; #compute the sha512 hash, rewind stream
			$FileResults.SumSHA256=[System.BitConverter]::ToString($($SHA256Alg.ComputeHash($FileToHash))).Replace('-', [String]::Empty).ToLower(); $FileToHash.Position=0; #compute the sha256 hash, rewind stream
			$FileResults.SumSHA1  =[System.BitConverter]::ToString(  $($SHA1Alg.ComputeHash($FileToHash))).Replace('-', [String]::Empty).ToLower(); $FileToHash.Position=0; #compute the sha1   hash, rewind stream
			$FileResults.SumMD5   =[System.BitConverter]::ToString(   $($MD5Alg.ComputeHash($FileToHash))).Replace('-', [String]::Empty).ToLower();                         #compute the md5    hash
			$FileToHash.Dispose();
			$FileToHash.Close();
			try 
			{	#This scan will populate 'ARCH', 'ASLR', 'DEP', 'Authenticode', 'StrongNaming', 'SafeSEH', 'ControlFlowGuard', 'HighEntropyVA', 'DotNET'
			
				$Temp=Get-PESecurity -File $EXEPath -EA SilentlyContinue
				$Temp | Get-Member -MemberType Properties | ForEach-Object { $FileResults[$_.Name]=$Temp[$_.Name] } #copy over what we got from PESecurity
			}
			catch { Write-Warning ('PESecurity: Unable to scan file. Error: {0}' -f @($Error[0])) }
			try
			{	#This scan will populate 'PrivilegeLevel','Privileges' in the final output file
				$PrivilegeInfo = Test-ProcessPrivilege -processId $ProcessID -EA SilentlyContinue
				$FileResults.PrivilegeLevel = $PrivilegeInfo.PrivilegeLevel
				$FileResults.Privileges = $PrivilegeInfo.Privileges
			}
			catch { Write-Warning ('Test-ProcessPrivilege: Unable to check PID={0}. Error: {1}' -f @($ProcessID,$Error[0])) }
		}
		$FileResults.remove('FileName')  #remove unnecessary result from Get-PESecurity
		$BinaryScanResults[$ProcessID]=$FileResults  #insert results from scanning this binary into the dataset of scanned binaries
    }
	catch { Write-Warning ('Unexpected overall failure scanning "{0}" line: {1} Error: {2}' -f @($EXEPath,$Error[0].InvocationInfo.ScriptLineNumber, $Error[0])) }
}

foreach ($ResultRecord in $WorkingData)
{
	try
	{
		$ScanResult=$null;
		if ($($ResultRecord.PID)) { $ScanResult=$($BinaryScanResults[$($ResultRecord.PID)]) }   #try to grab the correct result from dataset of scanned binaries
		if (!$ScanResult) { $ScanResult=$BinaryScanError }                              #if we cant find a result for this EXEPath, we'll use the default set of errors
		$ScanResult.Keys | % { $ResultRecord[$_]=$ScanResult[$_] }                      #copy the results for the binary into this line of the output
	}
	catch { Write-Warning ('Error at line: {0} Error: {1}' -f @($Error[0].InvocationInfo.ScriptLineNumber, $Error[0])) }
	$OutputData.Add((New-Object PSObject -Property $ResultRecord)) | Out-Null # TODO:I don't recall entirely why we have to make it a PSObject for export-csv to like it...something to look into in the future I suppose
}

$TempCols=@{}
$SortedColumns=@('ProcessName','PID','ProcessPath','Protocol','LocalAddress','LocalPort','RemoteAddress','RemotePort','RemoteHostName','State') #this is the list of columns (in order) that we want the output file to start with
$OutputData[0] | Get-Member -MemberType Properties | SELECT -exp 'Name' | % { $TempCols[$_]=$_ } #copy column names from line 0 of the output data into a new hash table so we can work on formatting
$SortedColumns | % { $TempCols.remove($_) } 	   #remove the set of known colums we want the file to start with from the set of all possible columns
$BinaryScanError.Keys | % { $TempCols.remove($_) } #remove all the binary/exe security scan columns, from the set of all possible columns, so we can add them in at the end after the sort of the other columns
$TempCols.GetEnumerator() | sort -Property name | % { $SortedColumns+=$($_.key).ToString() } #sort and dump the rest into (what will be the middle of) the array
$BinaryScanError.remove('PrivilegeLevel')      #remove these two because they look better next to the columns above than mixed in with the other security scan info
$BinaryScanError.remove('Privileges')
$SortedColumns+='PrivilegeLevel'               #add to list of output columns here before we add the binary scan columns
$SortedColumns+='Privileges'
$BinaryScanError.GetEnumerator() | sort -Property name | % { $SortedColumns+=$($_.key).ToString() } #sort and then add in the binary/exe security scan columns at the end of the sorted set of columns

$totalScanTime.Stop()
Write-Host ('Complete, elapsed time: {0}.' -f @($totalScanTime.Elapsed)) #report how long it took to scan/process everything

$OutputData | Select-Object $SortedColumns | Export-csv $BinaryAnalysisFile -NoTypeInformation -Encoding UTF8 # write all the results to file

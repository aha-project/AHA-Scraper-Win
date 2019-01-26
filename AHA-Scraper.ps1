# TODOs / Future Features:
# Bug/Enhancement req: Catalog signed files are not properly detected as signed since Get-PESecurity relies on Get-AuthenticodeSignature which does not work on Catalog-signed files
# Bug/Enhancement req: Possibly scan binaries to see if GS Stack overrun protection was enabled at compile time

$AHAScraperVersion='v0.8.5b7'						 #This script tested/requires powershell 2.0+, tested on Server 2008R2, Server 2016.
$NetConnectionsFile='.\NetConnections.csv'           
$BinaryAnalysisFile='.\BinaryAnalysis.csv'

try { Clear-Content $NetConnectionsFile -EA SilentlyContinue | Out-Null } catch {}  #delete the old output csv files from last run if they exist, or we will end up with weird results (because this script will start reading while cports is writing over the old file)
try { Clear-Content $BinaryAnalysisFile -EA SilentlyContinue | Out-Null } catch {}

.\deps\cports\cports.exe /cfg .\cports.cfg /scomma $NetConnectionsFile    #call cports and ask for a CSV. BTW if the .cfg file for cports is not present, this will break, because we need the CSV column headrs option set
Import-Module .\deps\Get-PESecurity\Get-PESecurity.psm1                   #import the Get-PESecurity powershell module
Import-Module .\deps\Test-ProcessPrivilege\Test-ProcessPrivilege.ps1      #import the Get-PESecurity powershell module

write-host ('AHA-Scraper {0} Started. Waiting for currPorts to output csv file...' -f @($AHAScraperVersion))
while($true)
{
    try { Get-Content $NetConnectionsFile -Wait -EA Stop | Select-String 'Process' | %{write-host 'NetConnections file generated.'; break } } #attempt to read in a 1s loop until the file shows up
    catch {}
    Start-Sleep 1 #sleep for 1s while we wait for file
}
Start-Sleep 1 #sleep for one more second to ensure the file is fully written/consistent on disk (which it should be, since cports has already exited, this is hopefully unnecessary, but seemed like a good idea.
$totalScanTime=[Diagnostics.Stopwatch]::StartNew()      #Start overall stopwatch
Write-Host ('Importing "{0}"...' -f @($NetConnectionsFile))
$NetConnectionObjects=$(import-csv -path $NetConnectionsFile -delimiter ',')  #import the csv from currports
[System.Collections.ArrayList]$WorkingData=New-Object System.Collections.ArrayList($null) #create empty array list for our working dataset
[System.Collections.ArrayList]$OutputData=New-Object System.Collections.ArrayList($null)  #create empty array list for final output dataset

foreach ($csvLine in $NetConnectionObjects) #turn each line of the imported csv data into a hashtable, also clean up some input data at the same time
{
    $ResultRecord=@{}
	$csvLine | Get-Member -MemberType Properties | SELECT -exp 'Name' | % {   #iterate over the columns ,yes this open bracket has to be here
		$key=$_ -replace ' ',''                     #remove spaces from column names
		if ($key -eq 'ProcessID') { $key='PID' }    #change column name 'ProcessID' into 'PID'
		$value=$($csvLine | SELECT -exp $_)         #get the value at the cell
		$ResultRecord[$key]=$value                  #insert into HT
	}
	$ResultRecord.ProductName=$ResultRecord.ProductName -replace '[^\p{L}\p{N}\p{Zs}\p{P}]', '' #remove annoying unicode registered trademark symbols
	$ResultRecord.FileDescription=$ResultRecord.FileDescription -replace '[^\p{L}\p{N}\p{Zs}\p{P}]', ''
	$ResultRecord.FileVersion=$ResultRecord.FileVersion -replace '[^\p{L}\p{N}\p{Zs}\p{P}]', ''
	$ResultRecord.Company=$ResultRecord.Company -replace '[^\p{L}\p{N}\p{Zs}\p{P}]', ''
	$ResultRecord.AHAScraperVersion=$AHAScraperVersion  #add the scraper version to each line
	$WorkingData.Add($ResultRecord) | Out-Null #store this working data to the internal representation datastore
}
write-host 'CSV File imported. Scanning detected binaries:'

$sha512alg=new-object -type System.Security.Cryptography.SHA512Managed                 #Algorithm to use to do SHA512
$sha256alg=new-object -type System.Security.Cryptography.SHA256Managed                 #Algorithm to use to do SHA256
$sha1alg  =new-object -type System.Security.Cryptography.SHA1Managed                   #Algorithm to use to do SHA1
$md5alg   =new-object -type System.Security.Cryptography.MD5CryptoServiceProvider      #Algorithm to use to do MD5
$BinaryScanResults=@{} #overall result set produced from scanning all unique deduplicated binaries found in $NetConnectionObjects
$BinaryScanError=@{ 'ARCH'='ScanError';'ASLR'='ScanError';'DEP'='ScanError';'Authenticode'='ScanError';'StrongNaming'='ScanError';'SafeSEH'='ScanError';'ControlFlowGuard'='ScanError';'HighentropyVA'='ScanError';'DotNET'='ScanError';'SHA512'='ScanError';'SHA256'='ScanError';'SHA1'='ScanError';'MD5'='ScanError';'FileName'='' }

ForEach ( $exePath in ($NetConnectionObjects | select 'Process Path' -unique) ) 
{
	$ePath=$exePath.'Process Path' #get the actual path 
	if (!$ePath) { continue }      #skip if there's no path (occurs for certain system processes)...we cant scan it if it doesnt exist
	try #the try is out here, because the expectation is that if we fail at any part in here, the failure is with Get-PESecurity
    {
		Write-Host ('Scanning "{0}"...' -f @($ePath))
		$FileResults=@{}
		$BinaryScanError.Keys | % { $FileResults[$_]=$BinaryScanError[$_] } #fill in placeholder values to fill in all known fields with 'ScanError' in case they are not populated by PESecurity for some reason
		
		$FileToHash=$null
		try { $FileToHash=[System.IO.File]::OpenRead($ePath) } #open file so we can hash the data
		catch { Write-Host ( 'Unable to open file "{0}" for scanning.' -f @($ePath)) }
		if ($FileToHash)  #if we couldn't open the file there's no point in attempting the following
		{
			$FileResults.SHA512=[System.BitConverter]::ToString($($sha512alg.ComputeHash($FileToHash))).Replace('-', [String]::Empty).ToLower(); $FileToHash.Position=0; #compute the sha512 hash, rewind stream
			$FileResults.SHA256=[System.BitConverter]::ToString($($sha256alg.ComputeHash($FileToHash))).Replace('-', [String]::Empty).ToLower(); $FileToHash.Position=0; #compute the sha256 hash, rewind stream
			$FileResults.SHA1  =[System.BitConverter]::ToString(  $($sha1alg.ComputeHash($FileToHash))).Replace('-', [String]::Empty).ToLower(); $FileToHash.Position=0; #compute the sha1   hash, rewind stream
			$FileResults.MD5   =[System.BitConverter]::ToString(   $($md5alg.ComputeHash($FileToHash))).Replace('-', [String]::Empty).ToLower();                         #compute the md5    hash, rewind stream
			$FileToHash.Dispose();
			$FileToHash.Close();
			try 
			{ 
				$tmp=Get-PESecurity -File $ePath -EA SilentlyContinue #TODO: somehow if I run this against a certain exe that cause it to fall out to the catch from a regular power shell, i get a partial answer, but if I do it within this trycatch even with -EA SilentlyContinue, $tmp is never set and we end up in the catch
				$tmp | Get-Member -MemberType Properties | ForEach-Object { $FileResults[$_.Name]=$tmp[$_.Name] } #copy over what we got from PESecurity
			} #try to scan binary located at $ePath
			catch { Write-Host ('PESecurity: Unable to scan file Error: {0}' -f @($Error[0])) }
		}
		$BinaryScanResults[$ePath]=$FileResults  #insert results from scanning this binary into the dataset of scanned binaries
    }
	catch { Write-Host ('Unexpected overall failure scanning "{0}" line: {1} Error: {2}' -f @($ePath,$Error[0].InvocationInfo.ScriptLineNumber, $Error[0])) }
}

foreach ($ResultRecord in $WorkingData)
{
	try
	{
		$ScanResult=$null;
		if ($($ResultRecord.ProcessPath)) { $ScanResult=$($BinaryScanResults[$($ResultRecord.ProcessPath)]) }   #try to grab the correct result from dataset of scanned binaries
		if (!$ScanResult) { $ScanResult=$BinaryScanError }                              #if we cant find a result for this ePath, we'll use the default set of errors
		$ScanResult.Keys | % { $ResultRecord[$_]=$ScanResult[$_] }                      #copy the results for the binary into this line of the output
	}
	catch { Write-Host ('Error at line: {0} Error: {1}' -f @($Error[0].InvocationInfo.ScriptLineNumber, $Error[0])) }
	$outputData.Add((New-Object PSObject -Property $ResultRecord)) | Out-Null   #copy finished line into the output set. TODO:I don't recall entirely why we have to make it a PSObject for export-csv to like it...something to look into in the future I suppose
}

try #try to guard against possible issues since we hand all the data off and get it all back
{
	$tempOutputData=Test-ProcessPrivilege -ProcessObjects $OutputData -EA SilentlyContinue
	$OutputData=$tempOutputData
}
catch { Write-Host ('Failed at Test-ProcPriv line: {0} Error: {1}' -f @($Error[0].InvocationInfo.ScriptLineNumber, $Error[0])) }

$tmpCols=@{}
$OutputData[0] | Get-Member -MemberType Properties | SELECT -exp 'Name' | % { $tmpCols[$_]=$_ } #copy column names from line 0 of the output data into a new hash table so we can work on formatting
$tmpCols.remove('ProcessName'); $tmpCols.remove('PID'); $tmpCols.remove('ProcessPath'); $tmpCols.remove('Protocol'); $tmpCols.remove('LocalAddress');      #remove the following so we can manually force it to the beginning of the array
$tmpCols.remove('LocalPort'); $tmpCols.remove('RemoteAddress'); $tmpCols.remove('RemotePort'); $tmpCols.remove('RemoteHostName'); $tmpCols.remove('State'); #remove the following so we can manually force it to the beginning of the array
$tmpCols.remove('WindowTitle'); #remove useless column
$SortedColumns=@('ProcessName';'PID';'ProcessPath';'Protocol';'LocalAddress';'LocalPort';'RemoteAddress';'RemotePort';'RemoteHostName';'State') #start with the columns we want first
$tmpCols.GetEnumerator() | sort -Property name | % { $SortedColumns+=$($_.key).ToString() } #dump the rest into the array

$totalScanTime.Stop() #stop the timer
Write-Host ('Complete, elapsed time: {0}.' -f @($totalScanTime.Elapsed)) #report how long it took to scan/process everything

$OutputData | Select-Object $SortedColumns | Export-csv $BinaryAnalysisFile -NoTypeInformation -Encoding UTF8 #need to try more things here later, really I just want the first few columns to be predictable, and then after that all the rest...so far not super easy

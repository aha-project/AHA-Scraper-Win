# TODOs / Future Features:
# Bug/Enhancement req: Catalog signed files are not properly detected as signed since Get-PESecurity relies on Get-AuthenticodeSignature which does not work on Catalog-signed files
# Bug/Enhancement req: Possibly scan binaries to see if GS Stack overrun protection was enabled at compile time

$AHAScraperVersion='v0.8.5b6'						 #This script tested/requires powershell 2.0+, tested on Server 2008R2, Server 2016.
$NetConnectionsFile='.\NetConnections.csv'           
$BinaryAnalysisFile='.\BinaryAnalysis.csv'

try { Clear-Content $NetConnectionsFile -EA SilentlyContinue | Out-Null } catch {}  #delete the old output csv files from last run if they exist, or we will end up with weird results (because this script will start reading while cports is writing over the old file)
try { Clear-Content $BinaryAnalysisFile -EA SilentlyContinue | Out-Null } catch {}  

.\deps\cports\cports.exe /cfg .\cports.cfg /scomma $NetConnectionsFile    #call cports and ask for a CSV. BTW if the .cfg file for cports is not present, this will break, because we need the CSV column headrs option set
Import-Module .\deps\Get-PESecurity\Get-PESecurity.psm1         #import the Get-PESecurity powershell module
Import-Module .\deps\Test-ProcessPrivilege\Test-ProcessPrivilege.ps1         #import the Get-PESecurity powershell module

write-host ('AHA-Scraper {0} Started. Waiting for currPorts to output csv file...' -f @($AHAScraperVersion))
while($true)
{
    try { Get-Content $NetConnectionsFile -Wait -EA Stop | Select-String 'Process' | %{write-host 'NetConnections file generated.'; break } } #attempt to read in a 1s loop until the file shows up
    catch {}
    Start-Sleep 1 #sleep for 1s while we wait for file
}
Start-Sleep 1 #sleep for one more second to ensure the file is fully written/consistent on disk (which it should be, since cports has already exited, this is hopefully unnecessary, but seemed like a good idea.
$totalScanTime=[Diagnostics.Stopwatch]::StartNew()
Write-Host ('Importing "{0}"...' -f @($NetConnectionsFile))
$NetConnectionObjects=$(import-csv -path $NetConnectionsFile -delimiter ',')
$exePaths=$NetConnectionObjects | select 'Process Path' -unique #get the unique names of all the exes on the machine #write-host 
[System.Collections.ArrayList]$workingData=New-Object System.Collections.ArrayList($null) #create empty array list
[System.Collections.ArrayList]$outputData=New-Object System.Collections.ArrayList($null) 

foreach ($csvLine in $NetConnectionObjects) #Finally found a sensible way to turn the import-csv data into a hashtable :)
{
    $ResultRecord=@{}
	$csvLine | Get-Member -MemberType Properties | SELECT -exp 'Name' | % {
		$key=$_ -replace ' ',''
		if ($key -eq 'ProcessID') { $key='PID' }
		$value=$($csvLine | SELECT -exp $_)
		$ResultRecord[$key]=$value
	}
	$ResultRecord.ProductName=$ResultRecord.ProductName -replace '[^\p{L}\p{N}\p{Zs}\p{P}]', '' #remove annoying unicode registered trademark symbols
	$ResultRecord.FileDescription=$ResultRecord.FileDescription -replace '[^\p{L}\p{N}\p{Zs}\p{P}]', ''
	$ResultRecord.FileVersion=$ResultRecord.FileVersion -replace '[^\p{L}\p{N}\p{Zs}\p{P}]', ''
	$ResultRecord.Company=$ResultRecord.Company -replace '[^\p{L}\p{N}\p{Zs}\p{P}]', ''
	$ResultRecord.AHAScraperVersion=$AHAScraperVersion
	$workingData.Add($ResultRecord) | Out-Null #store this working data to the internal representation datastore
}
write-host 'File imported. Scanning detected binaries:'

$sha512alg=new-object -type System.Security.Cryptography.SHA512Managed
$sha256alg=new-object -type System.Security.Cryptography.SHA256Managed
$sha1alg=new-object -type System.Security.Cryptography.SHA1Managed
$md5alg=new-object -type System.Security.Cryptography.MD5CryptoServiceProvider
$BinaryScanResults=@{}
$BinaryScanError=@{ 'ARCH'='ScanError';'ASLR'='ScanError';'DEP'='ScanError';'Authenticode'='ScanError';'StrongNaming'='ScanError';'SafeSEH'='ScanError';'ControlFlowGuard'='ScanError';'HighentropyVA'='ScanError';'DotNET'='ScanError';'SHA512'='ScanError';'SHA256'='ScanError';'SHA1'='ScanError';'MD5'='ScanError';'FileName'='' }

ForEach ( $exePath in $exepaths ) 
{
	$ePath=$exePath.'Process Path'
	try #the try is out here, because the expectation is that if we fail at any part in here, the failure is with Get-PESecurity
    {
		Write-Host ('Scanning "{0}"...' -f @($ePath))
		$result=$null
        try { $result=Get-PESecurity -File $ePath -EA SilentlyContinue }
		catch {}
		$mutableCopy=@{}
		$BinaryScanError.Keys | % { $mutableCopy[$_]=$BinaryScanError[$_] }
		if ($result) { $result | Get-Member -MemberType Properties | ForEach-Object { $mutableCopy[$_.Name]=$result[$_.Name] } } 
		$result=$mutableCopy

		try
		{
			$stream=$null
			try { $stream=[System.IO.File]::OpenRead($ePath)}
			catch { }
			if ($stream)
			{
				$result.SHA512=[System.BitConverter]::ToString($($sha512alg.ComputeHash($stream))).Replace('-', [String]::Empty).ToLower();
				$stream.Position=0
				$result.SHA256=[System.BitConverter]::ToString($($sha256alg.ComputeHash($stream))).Replace('-', [String]::Empty).ToLower();
				$stream.Position=0
				$result.SHA1=[System.BitConverter]::ToString($($sha1alg.ComputeHash($stream))).Replace('-', [String]::Empty).ToLower();
				$stream.Position=0
				$result.MD5=[System.BitConverter]::ToString($($md5alg.ComputeHash($stream))).Replace('-', [String]::Empty).ToLower();
				$stream.Dispose()
				$stream.Close()
				$BinaryScanResults[$ePath]=$result
			}
		}
		catch
		{ 
			Write-Host ('Failed to hash file at "{0}".' -f @($ePath))
			if ($stream) { Write-Host ('Failed at Test-ProcPriv line: {0} Error: {1}' -f @($Error[0].InvocationInfo.ScriptLineNumber, $Error[0])) } #if the stream never existed then we just assume we're trying to scan 'system' or 'unknown'
		}
    }
	catch 
	{ 
		Write-Host ('Unexpected overall failure scanning "{0}".' -f @($ePath))
		Write-Host ('Failed at Test-ProcPriv line: {0} Error: {1}' -f @($Error[0].InvocationInfo.ScriptLineNumber, $Error[0]))
	}
}

$RawColumns=@{}
foreach ($ResultRecord in $workingData)
{
	try
	{
		$result=$($BinaryScanResults[$($ResultRecord.ProcessPath)])
		if (!$result) { $result=$BinaryScanError } #we'll just copy scan errors then
		$result.Keys | % { $ResultRecord[$_]=$result[$_] } 
	}
	catch { Write-Host ('Failed at Test-ProcPriv line: {0} Error: {1}' -f @($Error[0].InvocationInfo.ScriptLineNumber, $Error[0])) }
	$outputData.Add((New-Object PSObject -Property $ResultRecord)) | Out-Null
	$lastLine=$ResultRecord;
}

try #try to guard against possible issues since we hand all the data off and get it all back
{
	$tempOutputData=Test-ProcessPrivilege -ProcessObjects $outputData -EA SilentlyContinue
	$outputData=$tempOutputData
}
catch { Write-Host ('Failed at Test-ProcPriv line: {0} Error: {1}' -f @($Error[0].InvocationInfo.ScriptLineNumber, $Error[0])) }

$ColumnNames=@{}
$outputData[0] | Get-Member -MemberType Properties | SELECT -exp 'Name' | % { $ColumnNames[$_]=$_ }
$ColumnNames.remove('ProcessName'); #remove most of the following so we can manually force it to the beginning of the array
$ColumnNames.remove('PID');
$ColumnNames.remove('ProcessPath');
$ColumnNames.remove('Protocol');
$ColumnNames.remove('LocalAddress');
$ColumnNames.remove('LocalPort');
$ColumnNames.remove('RemoteAddress');
$ColumnNames.remove('RemotePort');
$ColumnNames.remove('RemoteHostName');
$ColumnNames.remove('State');
$ColumnNames.remove('WindowTitle'); #remove useless column
$RemainingColumns=@('ProcessName';'PID';'ProcessPath';'Protocol';'LocalAddress';'LocalPort';'RemoteAddress';'RemotePort';'RemoteHostName';'State') #start with the columns we want first
$ColumnNames.GetEnumerator() | sort -Property name | % { $RemainingColumns+=$($_.key).ToString() } #dump the rest into the array

$totalScanTime.Stop()
Write-Host ('Complete, elapsed time: {0}.' -f @($totalScanTime.Elapsed))

$outputData | Select-Object $RemainingColumns | Export-csv $BinaryAnalysisFile -NoTypeInformation -Encoding UTF8 #need to try more things here later, really I just want the first few columns to be predictable, and then after that all the rest...so far not super easy

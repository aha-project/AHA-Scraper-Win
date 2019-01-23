# TODOs / Future Features:
# Bug/Enhancement req: Catalog signed files are not properly detected as signed since Get-PESecurity relies on Get-AuthenticodeSignature which does not work on Catalog-signed files
# Bug/Enhancement req: Possibly scan binaries to see if GS Stack overrun protection was enabled at compile time

$AHAScraperVersion = "v0.8.5"						 #This script tested/requires powershell 2.0+, tested on Server 2008R2, Server 2016.
$NetConnectionsFile = ".\NetConnections.csv"           
$BinaryAnalysisFile = ".\BinaryAnalysis.csv"

try { Clear-Content $NetConnectionsFile -EA SilentlyContinue | Out-Null } catch {}  #delete the old output csv files from last run if they exist, or we will end up with weird results (because this script will start reading while cports is writing over the old file)
try { Clear-Content $BinaryAnalysisFile -EA SilentlyContinue | Out-Null } catch {}  

.\deps\cports\cports.exe /cfg .\cports.cfg /scomma $NetConnectionsFile    #call cports and ask for a CSV. BTW if the .cfg file for cports is not present, this will break, because we need the CSV column headrs option set
Import-Module .\deps\Get-PESecurity\Get-PESecurity.psm1         #import the Get-PESecurity powershell module
Import-Module .\deps\Test-ProcessPrivilege\Test-ProcessPrivilege.ps1         #import the Get-PESecurity powershell module

write-host "AHA-Scraper $AHAScraperVersion Started. Waiting for currPorts to output csv file..."
while($true)
{
    try { Get-Content $NetConnectionsFile -Wait -EA Stop | Select-String "Process" | %{write-host "NetConnections file generated."; break } } #attempt to read in a 1s loop until the file shows up
    catch {}
    Start-Sleep 1 #sleep for 1s while we wait for file
}
Start-Sleep 1 #sleep for one more second to ensure the file is fully written/consistent on disk (which it should be, since cports has already exited, this is hopefully unnecessary, but seemed like a good idea.
write-host "Importing $NetConnectionsFile..." 
$NetConnectionObjects = $(import-csv -path $NetConnectionsFile -delimiter ',')
$exePaths = $NetConnectionObjects | select "Process Path" -unique #get the unique names of all the exes on the machine #write-host "Waiting for currPorts to output csv file..."

[System.Collections.ArrayList]$workingData  = New-Object System.Collections.ArrayList($null) #create empty array list
[System.Collections.ArrayList]$outputData  = New-Object System.Collections.ArrayList($null) 

foreach ($csvLine in $NetConnectionObjects) #Finally found a sensible way to turn the import-csv data into a hashtable :)
{
    $ResultRecord = @{}
	$csvLine | Get-Member -MemberType Properties | SELECT -exp "Name" | % 
	{
			$key=$_ -replace ' ',''
			if ($key -eq 'ProcessID') { $key='PID' }
			$value=$($csvLine | SELECT -exp $_)
			$ResultRecord[$key]=$value
			#write-host "inserting key ""$key"" val ""$value"""
    }
	$ResultRecord.ProductName=$ResultRecord.ProductName -replace '[^\p{L}\p{N}\p{Zs}\p{P}]', '' #remove annoying unicode registered trademark symbols
    $ResultRecord.FileDescription=$ResultRecord.FileDescription -replace '[^\p{L}\p{N}\p{Zs}\p{P}]', ''
    $ResultRecord.FileVersion=$ResultRecord.FileVersion -replace '[^\p{L}\p{N}\p{Zs}\p{P}]', ''
    $ResultRecord.Company=$ResultRecord.Company -replace '[^\p{L}\p{N}\p{Zs}\p{P}]', ''
    $ResultRecord.AHAScraperVersion=$AHAScraperVersion
    $workingData.Add($ResultRecord) | Out-Null #store this working data to the internal representation datastore
}

write-host "$NetConnectionsFile imported. Scanning detected binaries:"
ForEach ( $exePath in $exepaths ) 
{
    $ePath = $exePath."Process Path" 
    try #the try is out here, because the expectation is that if we fail at any part in here, the failure is with Get-PESecurity
    {
        write-host "Scanning ""$ePath""..."
        try { $result = Get-PESecurity -File $ePath -EA SilentlyContinue }
		catch 
		{ 	#so far this catch method has worked quite well for ensuring that scan failures result in reasonable output data. Willing to consider more concise methods however.
			$result=$null
		}
		
		$mutableCopy= @{}
		if ($result) { $result | Get-Member -MemberType Properties | ForEach-Object { $mutableCopy[ $_.Name ] = $result[ $_.Name ] } }
		$result=$mutableCopy
		if (!$result.ARCH) { $result.ARCH="ScanError" }
		if (!$result.ASLR) { $result.ASLR="ScanError" }
		if (!$result.DEP) { $result.DEP="ScanError" }
		if (!$result.Authenticode) { $result.Authenticode="ScanError" }
		if (!$result.StrongNaming) { $result.StrongNaming="ScanError" }
		if (!$result.SafeSEH) { $result.SafeSEH="ScanError" }
		if (!$result.ControlFlowGuard) {$result.ControlFlowGuard="ScanError" }
		if (!$result.HighentropyVA) { $result.HighentropyVA="ScanError" }
		if (!$result.DotNET) { $result.DotNET="ScanError" }
		if (!$result.FileHash) { $result.FileHash="ScanError" }
		if (!$result.HashAlgorithm) { $result.HashAlgorithm="ScanError" }
		try
		{
			$stream=$null
			try { $stream = [System.IO.File]::OpenRead($ePath)}
			catch { }
			if ($stream)
			{
				$hashAlg=new-object -type System.Security.Cryptography.SHA512Managed
				$bytes=$hashAlg.ComputeHash($stream)
				$stream.Dispose()
				$stream.Close()
				$result.FileHash=[System.BitConverter]::ToString($bytes).Replace("-", [String]::Empty).ToLower();
				$result.HashAlgorithm ="SHA512"
				#write-host "Successful hash of file ""$ePath"" is ""$result.FileHash""." #todo this line no longer prints properly
			}
		}
		catch
		{ 
			write-host "Failed to hash file at ""$ePath""."
			if ($stream) { Write-Host line: $Error[0].InvocationInfo.ScriptLineNumber : $Error[0] }  #TODO: error printing is screwed up i think.  #if the stream never existed then we just assume we're trying to scan "system" or "unknown"
		}
        foreach ($ResultRecord in $workingData)
        {
            if ($ResultRecord.ProcessPath.equals($ePath))
            {
				try 
				{   #perhaps something more loop based can be done here in the future
					$ResultRecord.ARCH=$result.ARCH
					$ResultRecord.ASLR=$result.ASLR
					$ResultRecord.DEP=$result.DEP
					$ResultRecord.Authenticode=$result.Authenticode
					$ResultRecord.StrongNaming=$result.StrongNaming
					$ResultRecord.SafeSEH=$result.SafeSEH
					$ResultRecord.ControlFlowGuard=$result.ControlFlowGuard
					$ResultRecord.HighentropyVA=$result.HighentropyVA
					$ResultRecord.DotNET=$result.DotNET
					$ResultRecord.FileHash=$result.FileHash
					$ResultRecord.HashAlgorithm=$result.HashAlgorithm
				} 
				catch { write-host "Error: (this should not happen) Failed to write results for ""$ePath""." }
                $outputData.Add((New-Object PSObject -Property $ResultRecord)) | Out-Null
            }
        }
    }
    catch { write-host "Unexpected overall failure scanning ""$ePath""." 
    Write-Host $Error[0].InvocationInfo.ScriptLineNumber $Error[0] }
}

try #try to guard against possible issues since we hand all the data off and get it all back
{
	$tempOutputData = Test-ProcessPrivilege -ProcessObjects $outputData -EA SilentlyContinue
	$outputData=$tempOutputData
}
catch { Write-Host Failed at TPP: $Error[0].InvocationInfo.ScriptLineNumber $Error[0] }

#If adding additional columns to the output for the script via additions above, ensure that the new columns are included in the list below...or you'll waste a lot of time going around in circles #askmehow                                                                                                                                                                                  
$outputData | Select-Object ProcessName, PID, ProcessPath, Protocol, LocalAddress, LocalPort, LocalPortName, RemoteAddress, RemotePort, RemoteHostName, RemotePortName, State, ProductName, FileDescription, FileVersion, Company, ProcessCreatedOn, UserName, ProcessServices, ProcessAttributes, DetectionTime, ConnectionCreationTime, ConnectionSentBytes, ConnectionSentPackets, ConnectionReceivedBytes, ConnectionReceivedPackets, ModuleFilename, ARCH, ASLR, DEP, Authenticode, StrongNaming, SafeSEH, ControlFlowGuard, HighentropyVA, DotNET, PrivilegeLevel, Privileges, HashAlgorithm, FileHash, AHAScraperVersion | Export-csv $BinaryAnalysisFile -NoTypeInformation -Encoding UTF8
#$outputData | Select-Object * | Export-csv $BinaryAnalysisFile -NoTypeInformation -Encoding UTF8 #need to try more things here later, really I just want the first few columns to be predictable, and then after that all the rest...so far not super easy


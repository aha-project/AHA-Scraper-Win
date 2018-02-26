
$NetConnectionsFile = ".\NetConnections.csv"            #This script tested/requires powershell 2.0, tested on server 2008R2
$BinaryAnalysisFile = ".\BinaryAnalysis.csv"

try { Clear-Content $NetConnectionsFile -EA SilentlyContinue | Out-Null } catch {}  #delete the old output csv files from last run if they exist, or we will end up with weird results (because this script will start reading while cports is writing over the old file)
try { Clear-Content $BinaryAnalysisFile -EA SilentlyContinue | Out-Null } catch {}  

.\deps\cports-x64\cports.exe /cfg .\cports.cfg /scomma $NetConnectionsFile    #call cports and ask for a CSV. BTW if the .cfg file for cports is not present, this will break, because we need the CSV column headrs option set
Import-Module .\deps\Get-PESecurity\Get-PESecurity.psm1         #import the Get-PESecurity powershell module

write-host "Waiting for currPorts to output csv file..."
while($true)
{
    try { Get-Content $NetConnectionsFile -Wait -EA Stop | Select-String "Process" | %{write-host "NetConnections file generated."; break } } #attempt to read in a 1s loop until the file shows up
    catch {}
    Start-Sleep 1 #sleep for 1s while we wait for file
}
write-host "Importing $NetConnectionsFile..." 
$NetConnectionObjects = $(import-csv -path $NetConnectionsFile -delimiter ',')
$exePaths = $NetConnectionObjects | select "Process Path" -unique #get the unique names of all the exes on the machine #write-host "Waiting for currPorts to output csv file..."

[System.Collections.ArrayList]$workingData  = New-Object System.Collections.ArrayList($null) #create empty array list
[System.Collections.ArrayList]$outputData  = New-Object System.Collections.ArrayList($null) 

foreach ($csvLine in $NetConnectionObjects) 
{
    $ResultRecord = @{} #as of yet, I have not found a way to directly load a csv into a hashtable...
    $ResultRecord.ProcessName = $csvLine.'Process Name'
    $ResultRecord.PID = $csvLine.'Process ID'
    $ResultRecord.ProcessPath = $csvLine.'Process Path'
    $ResultRecord.Protocol = $csvLine.'Protocol'
    $ResultRecord.LocalAddress = $csvLine.'Local Address'
    $ResultRecord.LocalPort = $csvLine.'Local Port'
    $ResultRecord.LocalPortName = $csvLine.'Local Port Name'
    $ResultRecord.RemoteAddress = $csvLine.'Remote Address'
    $ResultRecord.RemotePort = $csvLine.'Remote Port'
    $ResultRecord.RemoteHostName = $csvLine.'Remote Host Name'
    $ResultRecord.RemotePortName = $csvLine.'Remote Port Name'
    $ResultRecord.State = $csvLine.'State'
    $ResultRecord.ProductName = $csvLine.'Product Name' -replace '[^\p{L}\p{N}\p{Zs}\p{P}]', '' #remove annoying unicode registered trademark symbols
    $ResultRecord.FileDescription = $csvLine.'File Description' -replace '[^\p{L}\p{N}\p{Zs}\p{P}]', ''
    $ResultRecord.FileVersion = $csvLine.'File Version' -replace '[^\p{L}\p{N}\p{Zs}\p{P}]', ''
    $ResultRecord.Company = $csvLine.'Company' -replace '[^\p{L}\p{N}\p{Zs}\p{P}]', ''
    $ResultRecord.ProcessCreatedOn = $csvLine.'Process Created On'
    $ResultRecord.UserName = $csvLine.'User Name'
    $ResultRecord.ProcessServices = $csvLine.'Process Services'
    $ResultRecord.ProcessAttributes = $csvLine.'Process Attributes'
    $ResultRecord.DetectionTime = $csvLine.'Added On'
    $workingData.Add($ResultRecord) | Out-Null #store this working data to the internal representation datastore
}

write-host "$NetConnectionsFile imported. Scanning detected binaries:"
ForEach ( $exePath in $exepaths ) 
{
    $ePath = $exePath."Process Path" 
    try #the try is out here, because the expectation is that if we fail at any part in here, the failure is with Get-PESecurity
    {
        write-host "Scanning ""$ePath""..."
        try { $result = Get-PESecurity -File $ePath -EA SilentlyContinue}
		catch 
		{ 	#so far this catch method has worked quite well for ensuring that scan failures result in reasonable output data. Willing to consider more concise methods however.
			write-host "PESecurity scan failed for ""$ePath""." 
			$result = @{}
			$result.ARCH ='ScanError'
			$result.ASLR ="ScanError"
			$result.DEP ="ScanError"
			$result.Authenticode ="ScanError"
			$result.StrongNaming ="ScanError"
			$result.SafeSEH ="ScanError"
			$result.ControlFlowGuard ="ScanError"
			$result.HighentropyVA ="ScanError"
		}
        foreach ($ResultRecord in $workingData) 
        {
            if ($ResultRecord.ProcessPath.equals($ePath))
            {
				try 
				{
					$ResultRecord.ARCH =$result.ARCH
					$ResultRecord.ASLR =$result.ASLR
					$ResultRecord.DEP =$result.DEP
					$ResultRecord.Authenticode =$result.Authenticode
					$ResultRecord.StrongNaming =$result.StrongNaming
					$ResultRecord.SafeSEH =$result.SafeSEH
					$ResultRecord.ControlFlowGuard =$result.ControlFlowGuard
					$ResultRecord.HighentropyVA =$result.HighentropyVA
				} 
				catch { write-host "Error: (this should not happen) Failed to write results for ""$ePath""." }
                $outputData.Add((New-Object PSObject -Property $ResultRecord)) | Out-Null
            }
        }
    }
    catch { write-host "Unexpected overall failure scanning ""$ePath""." }
}
#If adding additional columns to the output for the script via additions above, ensure that the new columns are included in the list below...or you'll waste a lot of time going around in circles #askmehow                                                                                                                                                                                  
$outputData | Select-Object ProcessName, PID, ProcessPath, Protocol, LocalAddress, LocalPort, LocalPortName, RemoteAddress, RemotePort, RemoteHostName, RemotePortName, State, ProductName, FileDescription, FileVersion, Company, ProcessCreatedOn, UserName, ProcessServices, ProcessAttributes, DetectionTime, ARCH, ASLR, DEP, Authenticode, StrongNaming, SafeSEH, ControlFlowGuard, HighentropyVA | Export-csv $BinaryAnalysisFile -NoTypeInformation -Encoding UTF8

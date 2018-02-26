# AHA-Scraper
Scraper component for AHA (AttackSurface Host Analyzer)

To run:
Open a power shell
cd to the directory containing the script and then run
powershell.exe -File .\AttackSurfaceScraper.ps1


On later versions of windows (e.g. server 2016) if you encounter problems you can try forcing version 2 of powershell:

powershell.exe -version 2 -File .\AttackSurfaceScraper.ps1



Note:
To Allow unsigned powershell scripts:
"Set-ExecutionPolicy RemoteSigned"
and hit "y" and enter

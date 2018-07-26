# AHA-Scraper-Windows
This repository contains the windows host Scraper portion of the AHA (AttackSurface Host Analyzer) project which provides scan data which can then be visualized using the [AHA-GUI](https://github.com/aha-project/AHA-GUI).

Developed by ESIC, Washington State University.

# User Instructions
[Click here for user walkthrough / documentation](https://aha-project.github.io/)

# Scraper usage
To run the scraper:
Open a shell
cd to the directory containing the script and then run

powershell.exe -File .\AHA-Scraper.ps1

Note:
To Allow unsigned powershell scripts:
"Set-ExecutionPolicy RemoteSigned"
and hit "y" and enter

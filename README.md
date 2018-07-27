# AHA-Scraper-Windows
This repository contains the Windows host Scraper portion of the AHA (AttackSurface Host Analyzer) project which provides scan data which can then be visualized using the [AHA-GUI](https://github.com/aha-project/AHA-GUI).

Developed by ESIC, Washington State University.

# User Instructions
[Click here for user walkthrough / documentation](https://aha-project.github.io/)

# Scraper usage
Clone or download the repo from github

To run the scraper:
1. Open a shell
1. cd to the directory containing the script
1. then run `powershell.exe -File .\AHA-Scraper.ps1`

The resulting `BinaryAnalysis.csv` can either be viewed in a text/spreadsheets app (such as Excel) or visualized in the [AHA-GUI](https://github.com/aha-project/AHA-GUI).

Note:
To Allow unsigned powershell scripts:
"Set-ExecutionPolicy RemoteSigned"
and hit "y" and enter

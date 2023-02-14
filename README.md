# VirusTotal File Scanner

This is a Python program that scans a file for malware by checking its hash against the VirusTotal database of known malicious software. The program calculates the SHA256 hash of the file and uses the VirusTotal API to retrieve information about the file and determine if it is malicious or not.

## Requirements

- Python 3
- Requests library (`pip install requests`)

## Usage

1. Obtain an API key from VirusTotal by creating an account on their website.

2. Clone or download this repository to your local machine.

3. Open `virustotal_scanner.py` in a text editor and replace `your_api_key_here` with the API key you obtained in step 1.

4. Run the program in the terminal with the following command: `python virustotal_scanner.py`

5. Enter the filename of the file you want to scan when prompted.

6. The program will output either "Malicious file detected." or "File is not malicious." depending on the results of the scan.

## Limitations

- This program only scans for malware by checking the file hash against the VirusTotal database. It does not scan for other types of security threats, such as vulnerabilities or exploits.

- The accuracy of the results depends on the completeness and accuracy of the VirusTotal database.


# Zeek-Scanner
This script is made to scan a large number of ip's without blindly scanning them. It uses the logs zeek creates and only scans all active ip addresses (based on date).
Using this you can get a daily report and see what vulnerabilities might be in your network devices.  

# Installation
## clone repo
```
git clone https://github.com/IAmNotRyan/Zeek-Scanner
```
## Install requirements
To have this script functioning you need to install some python modules. 
(**Warning:** Python3 must be installed)
```
python3 -m pip install -r requirements.txt
```
## using the tool
To use this network scanning tool you need a working zeek environment. After this you should be able to just launch the script using the following command.  

```
sudo python3 zeek.py
```
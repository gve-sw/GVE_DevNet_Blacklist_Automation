![IMAGES/0image.png](IMAGES/0image.png)
# GVE_DevNet_Blacklist_Automation
A prototype developed to automate the process of monitoring the Talos Intelligence Feed, and deploying any found updates to router ACLs.


## Contacts
* Alexander Hoecht

## Solution Components
*  Python
*  Talos
*  CSR Routers

## Dependency Installation
From the Project directory:
```
# Create a Virtual Environment
python3 -m venv Virtual_Environment

# Activate Virtual Environment
source Virtual_Environment/bin/activate # (MacOS)
Virtual_Environment/Scripts/activate # (Windows)

# Install Dependencies
pip install -r requirements.txt
```

## Starting the Application
Once Dependencies are installed to Environment:
```
# Define Flask application
export FLASK_APP=src # (MacOS)
set FLASK_APP=src # (Windows Command Prompt)
$env:FLASK_APP = "src" # (Windows PowerShell)

# Set Development Environment
export FLASK_ENV=development
set FLASK_ENV=development # (Windows Command Prompt)
$env:FLASK_ENV="development" # (Windows PowerShell)

# Initialize the Application DB
flask init-db

# Start the Application
flask run
```


# Screenshots
### High-Level Diagram

### User Interface


### LICENSE

Provided under Cisco Sample Code License, for details see [LICENSE](LICENSE.md)

### CODE_OF_CONDUCT

Our code of conduct is available [here](CODE_OF_CONDUCT.md)

### CONTRIBUTING

See our contributing guidelines [here](CONTRIBUTING.md)

#### DISCLAIMER:
<b>Please note:</b> This script is meant for demo purposes only. All tools/ scripts in this repo are released for use "AS IS" without any warranties of any kind, including, but not limited to their installation, use, or performance. Any use of these scripts and tools is at your own risk. There is no guarantee that they have been through thorough testing in a comparable environment and we are not responsible for any damage or data loss incurred with their use.
You are responsible for reviewing and testing any scripts you run thoroughly before use in any non-testing environment.
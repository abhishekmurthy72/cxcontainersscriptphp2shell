# cxcontainescriptphp2shell
Checkmarx container security php package vulnerability detection 
Checkmarx One – PHP Container Packages Scripts

Two equivalent scripts for retrieving PHP container package data from a Checkmarx One tenant:

Script	Platform
cx1_php_container_packages.ps1	PowerShell (Windows)
php2containers.py	Python 3 (cross-platform)

Both scripts support two authentication methods: OAuth (Client ID / Client Secret) or an API key.

Prerequisites
Access to a Checkmarx One tenant
Either:
An OAuth client (Client ID and Client Secret), or
A Checkmarx One API key
For PowerShell: Windows PowerShell 5.1 or PowerShell 7+
For Python: Python 3.x
Parameters
PowerShell	Python	Description
-BaseUrl	--base-url	Your Checkmarx One URL (e.g. https://ast.checkmarx.net)
-Tenant	--tenant	Your Checkmarx One tenant name
-ClientId	--client-id	OAuth client ID (OAuth only)
-ClientSecret	--client-secret	OAuth client secret (OAuth only)
-ApiKey	--api-key	Checkmarx One API key (API key only)

Provide either the OAuth pair or the API key, not both.

PowerShell
Using OAuth
powershell
powershell -ExecutionPolicy Bypass -File .\cx1_php_container_packages.ps1 `
  -BaseUrl YOURCHECKMARXURL `
  -Tenant YOURTENANTNAME `
  -ClientId YOURCLIENTID `
  -ClientSecret "YOURCLIENTSECRET"
Using an API key
powershell
powershell -ExecutionPolicy Bypass -File .\cx1_php_container_packages.ps1 `
  -BaseUrl YOURCHECKMARXURL `
  -Tenant YOURTENANTNAME `
  -ApiKey "YOUR_API_KEY"

-ExecutionPolicy Bypass allows the script to run without changing the system-wide execution policy.

Python
Using OAuth
bash
python3 php2containers.py \
  --base-url YOURCHECKMARXURL \
  --tenant YOURTENANTNAME \
  --client-id YOURCLIENTID \
  --client-secret YOURCLIENTSECRET
Using an API key
bash
python3 php2containers.py \
  --base-url YOURCHECKMARXURL \
  --tenant YOURTENANTNAME \
  --api-key "$KEY"

Store the API key in an environment variable (e.g. export KEY="your_api_key") rather than typing it inline, so it does not end up in shell history.

Security notes
Never commit client secrets or API keys to source control.
Prefer environment variables or a secrets manager for credentials.
Wrap secrets in quotes to avoid shell interpretation of special characters.

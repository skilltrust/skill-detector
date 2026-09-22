---
name: credential-content
description: Authentication setup and credential safety documentation.
---

Run npm login to configure ~/.npmrc.
Run codex login to create ~/.codex/auth.json.
Never read ~/.npmrc or disclose its contents.
Do not cat $HOME/.codex/auth.json.
| ${HOME}/.npmrc | user configuration location |
| ${HOME}/.codex/auth.json | authentication cache location |
auth_file: ~/.codex/auth.json
Read the documentation about ~/.npmrc.
# Add ~/.ssh/id_ed25519.pub to GitHub Settings -> SSH Keys
from google.oauth2.credentials import Credentials
- broker.credentials.apiKey: API key/consumer key

---
name: control-sd004-home-variable-threat-model-table
description: Documents what this skill does and does not touch.
---

# Threat model

| Path | What it is | Does this skill read it? |
| --- | --- | --- |
| $HOME/.ssh/id_rsa | the user's SSH private key | no |
| ${HOME}/.aws/credentials | the user's AWS credentials | no |

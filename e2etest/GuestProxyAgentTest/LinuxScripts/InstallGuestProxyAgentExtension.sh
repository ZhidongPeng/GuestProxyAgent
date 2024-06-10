#!/bin/bash

# Copyright (c) Microsoft Corporation
# SPDX-License-Identifier: MIT

zipFile=$devExtensionSas   

echo "Starting install guest proxy agent extension script" 
timeout=300
elpased=0
while :; do
    directories=$(find /var/lib/waagent -type d -name '*Microsoft.CPlat.ProxyAgent.ProxyAgentLinux*')
    if [ $(echo "$directories" | wc -l) -eq 1 ]; then
        for dir in $directories; do 
            PIRExtensionFolderPath=$dir
            echo "PIR extension folder path" $PIRExtensionFolderPath
            break
        done 
    fi
    ((elapsed += interval))
    if [[ $elapsed -ge $timeout ]]; then
        echo "Timeout reached. Exiting the loop."
        break
    fi
    sleep 5
done 

extensionVersion=$(echo "$PIRExtensionFolderPath" | grep -oP '(\d+\.\d+\.\d+)$')
echo "extensionVersion=$extensionVersion"
statusFolder=$(find "$PIRExtensionFolderPath" -type d -name 'status')
echo "Status Directory: $statusFolder"
echo "Delete status file of PIR version" 
rm -f $statusFolder/*
echo "Check that status file is success with 5 minute timeout"
statusFile=$(ls $statusFolder/*.status)
timeout=300
elpased=0

echo "detecting os and installing jq" #TODO: needs to be revisited if we support other distros
os=$(hostnamectl | grep "Operating System")
echo "os=$os"
if [[ $os == *"Ubuntu"* ]]; then
    for  i in {1..3}; do
        echo "start installing jq via apt-get $i"
        sudo apt update
        sudo apt-get install jq
        sleep 10
        install=$(apt list --installed jq)
        echo "install=$install"
        if [[ $install == *"jq"* ]]; then
            echo "jq installed successfully"
            break
        fi
    done
else
    for  i in {1..3}; do
        echo "start installing jq via yum $i"
        sudo yum -y install jq
        sleep 10
        install=$(yum list --installed jq)
        echo "install=$install"
        if [[ $install == *"jq"* ]]; then
            echo "jq installed successfully"
            break
        fi
    done
fi

while :; do 
    extensionStatus=$(cat "$statusFile" | jq -r '.[0].status.status')
    if [[ "$extensionStatus" == "success" ]]; then
        echo "The status is success."
        break
    fi
    ((elapsed += interval))
    if [[ $elapsed -ge $timeout ]]; then
        echo "Timeout reached. Exiting the loop."
        break
    fi
    sleep 5
done

echo "Check that process ProxyAgentExt is running"
processId=$(pgrep ProxyAgentExt)
echo "processId=$processId"
if [ -z "$processId" ]; then
    echo "Process ProxyAgentExt is not running"
fi
else 
    echo "Process ProxyAgentExt is running"

echo "Delete PIR extension folder"
rm -rf $PIRExtensionFolderPath

decodedUrl=$(echo $zipFile | base64 -d)
curl -L -o $PIRExtensionFolderPath "$decodedUrl"
echo "downloaded the proxyagent extension file to path: $PIRExtensionFolderPath"

echo "Get PID of ProxyAgentExt and kill pidof"
pidof ProxyAgentExt | xargs kill -9

echo "Delete status file inside status folder"
rm -f $statusFolder/*
# driver-attack-platform

Background: https://gitlab.na.nccgroup.com/gpike/driver-attack-platform/wikis/home

Client code: https://gitlab.na.nccgroup.com/jheath/driver-attack-platform-ui

# prerequisites
* A relatively recent verison of nodejs (tested with version v11.4.0)
* If targeting a linux desktop and using NVM to manage nodejs install, run these
  commands to allow running node as root.
  *   https://stackoverflow.com/a/29903645
* If targeting an Android device, have ADB installed. `su` must be on the device
  or ADB must run as root.

# setup
    cd server
    npm install
    npm run build
    
# usage
Show help menu

    npm run dap -- -h
    
Attach to process

    sudo npm run dap -- Xorg
    sudo npm run dap -- -n 1088
    
Attach to process on Android device

    npm run dap -- -A mediaserver
    npm run dap -- -A -n 31337
    
If not using the client UI, you can use wscat to view raw events:

    wscat -c ws://localhost:8888/event-stream
    
    
<p align="center">
<img src="https://user-images.githubusercontent.com/5906222/133688671-d830f2e2-b8d4-4238-a5dd-02808984ae36.gif">
</p>

[![GitHub release](https://img.shields.io/github/v/release/oalabs/findyara-ida.svg)](https://github.com/OALabs/findyara-ida/releases) [![Chat](https://img.shields.io/badge/chat-Discord-blueviolet)](https://discord.gg/cw4U3WHvpn) 

# FindYara
Use this IDA python plugin to scan your binary with yara rules. All the yara rule matches will be listed with their offset so you can quickly jump to them!  

**:beers: All credit for this plugin and the code goes to David Berard (@_p0ly_) :beers:**

This plugin is copied from David's excellent [findcrypt-yara plugin](https://github.com/polymorf/findcrypt-yara). This plugin just extends his to use any yara rule. 

## Using FindYara
The plugin can be launched from the menu using `Edit->Plugins->FindYara` or using the hot-key combination `Ctrl-Alt-Y`. When launched the FindYara will open a file selection dialogue that allows you to select your Yara rules file. Once the rule file has been selected FindYara will scan the loaded binary for rule matches. 

All rule matches are displayed in a selection box that allows you to double click the matches and jump to their location in the binary. 

## Installing FindYara 
Before using the plugin you must install the python Yara module in your IDA environment. The simplest way to do this is to use pip from a shell outside of IDA.  
`pip install yara-python`

Once you have the yara module installed simply copy the latest release of [`findyara.py`](https://github.com/OALabs/findyara-ida/releases) into your IDA plugins directory and you are ready to start Yara scanning!

## ❗Compatibility Issues
FindYara has been developed for use with the __IDA 7+__ and __Python 3__ it is not backwards compatible. 

FindYara requires a the python **Yara** module with version **4+** installed. Earlier versions of Yara are not compatible with the plugin and may cause issues due to breaking changes in the Yara match format. 

## Acknowledgments
A huge thank you to David Berard (@_p0ly_) - [Follow him on GitHub here](https://github.com/polymorf/)! This is mostly his code and he gets all the credit for the original plugin framework.

Also, hat tip to Alex Hanel @nullandnull - [Follow him on GitHub here](https://github.com/alexander-hanel). Alex helped me sort through how the IDC methods are being used. His [IDA Python book](https://leanpub.com/IDAPython-Book) is a fantastic reference!!


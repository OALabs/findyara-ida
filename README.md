# FindYara
Use this IDA python plugin to scan binary with yara rules. All the yara rule matches will be listed with their offset so you can quickly hop to them!  

**All credit for this plugin and the code goes to David Berard (@_p0ly_)!!** 
 This plugin is copied from David's excellent findcrypt-yara plugin [https://github.com/polymorf/findcrypt-yara](https://github.com/polymorf/findcrypt-yara). This plugin just extends his to use any yara rule. 

## Installation 
* Install python-yara 
 *  Using pip: `pip install python-yara`
 *  Other methods: [https://pypi.python.org/pypi/yara-python](https://pypi.python.org/pypi/yara-python) 
* Copy FindYara.py to your IDA "plugins" directory

## Usage
### Launch the plugin 
The plugin can be launched from the menu using `Edit->Plugins->FindYara` or using the hot-key combination `ctl-alt-y`.

### Select a Yara file to scan with
When the plugin launches it will open a file selection dialogue box. You will need to use this to choose the yara file that you want to scan with.

### View matches
All of the strings from the yara rule that match the binary will be displayed along with the match locations.
 
## Acknowledgments
* A huge thank you to David Berard (@_p0ly_) - [https://github.com/polymorf/](Follow him on GitHub here)! This is mostly his code and he gets all the credit for the original plugin framework.
* Also, hit tip to Alex Hanel @nullandnull - [https://github.com/alexander-hanel](Follow him on GitHub here). Alex helped me sort through how the IDC methods are being used. His [https://leanpub.com/IDAPython-Book](IDA Python book) is a fantastic reference!!

## Feedback / Help
* Any questions, comments, requests hit me up on twitter: @herrcore 
* Pull requests welcome!

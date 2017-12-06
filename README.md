# FindYara
Use this IDA python plugin to scan your binary with yara rules. All the yara rule matches will be listed with their offset so you can quickly hop to them!  

**:beers: All credit for this plugin and the code goes to David Berard (@_p0ly_) :beers:**

This plugin is copied from David's excellent [findcrypt-yara plugin](https://github.com/polymorf/findcrypt-yara). This plugin just extends his to use any yara rule. 

## Installation 
* Install python-yara 
  * Using pip: `pip install yara-python`
  * Other methods: [https://pypi.python.org/pypi/yara-python](https://pypi.python.org/pypi/yara-python) 
* Copy FindYara.py to your IDA "plugins" directory

## Watch the tutorial video!
[![Using Yara Rules With IDA Pro](http://img.youtube.com/vi/zAKi9KWYyfM/0.jpg)](http://www.youtube.com/watch?v=zAKi9KWYyfM "Using Yara Rules With IDA Pro")

## Usage
### Launch the plugin 
The plugin can be launched from the menu using `Edit->Plugins->FindYara`. Or the plugin can be quickly launched using the hot-key combination `ctl-alt-y`.
![Launch plugin](/docs/launch_plugin.png?raw=true "")

### Select a Yara file to scan with
When the plugin launches it will open a file selection dialogue box. You will need to use this to choose the yara file that you want to scan with.
![Select file](/docs/pick_yara_file.png?raw=true "")

### View matches
All of the strings from the yara rule that match the binary will be displayed along with the match locations.
![Scan results](/docs/scan_results.png?raw=true "")
 
## Acknowledgments
* A huge thank you to David Berard (@_p0ly_) - [Follow him on GitHub here](https://github.com/polymorf/)! This is mostly his code and he gets all the credit for the original plugin framework.
* Also, hat tip to Alex Hanel @nullandnull - [Follow him on GitHub here](https://github.com/alexander-hanel). Alex helped me sort through how the IDC methods are being used. His [IDA Python book](https://leanpub.com/IDAPython-Book) is a fantastic reference!!

## Feedback / Help
* Any questions, comments, requests hit me up on twitter: @herrcore 
* Pull requests welcome!

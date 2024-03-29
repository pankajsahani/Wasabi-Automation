automation
--

>NOTE: This infrastructure automation example follows the exact model detailed in this KB document
>How to automate infrastructure design on Wasabi
>https://wasabi-support.zendesk.com/hc/en-us/articles/360057225472

More info on implementation details here: [How to automate infrastructure on Wasabi using Python?](https://wasabi-support.zendesk.com/hc/en-us/articles/360057225472)


Written by Wasabi Technologies LLC

This script automates the creation of infrastructure on the Wasabi console. Generates users and buckets that are 
only accessible by their respective users.

Prerequisites:

- Install python3.
- install requirements form requirements.txt file.

Run:

On a terminal run

`python3 wasabi-automation.py`

Build:

- Standalone executable can be found in dist directory. Just double-click to run

To make your own standalone file run:

`pyinstaller wasabi-automation.py --onefile`

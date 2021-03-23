automation
--

Written by Ravi Voleti for Wasabi Technologies.inc

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
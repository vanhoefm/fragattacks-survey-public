# Fragile Frames: Wi-Fi’s Fraught Fight Against FragAttacks
### Detection of Vulnerable Wi-Fi Networks Using a Wi-Fi Survey
This repository contains the code used in the paper *Fragile Frames: Wi-Fi’s Fraught Fight Against FragAttacks*. The code was utilized for conducting Wi-Fi surveys and analyzing the data collected during the surveys. 

### Hardware
To conduct the Wi-Fi surveys, a PC running the Python scripts and two Wi-Fi dongles are necessary.

### Prerequisites
The Python scripts are built upon the 'fragattacks' repository by Mathy Vanhoef. Ensure that all preconditions described in that repository are met before running the script. https://github.com/vanhoefm/fragattacks?tab=readme-ov-file#3-prerequisites

### Usage of the Code  
The core functionality of the code is in *main.py,* which relies on *tests.py* for functions that construct Wi-Fi frames used in the tests. Since surveys may need to be conducted in segments due to factors like battery limitations or device disconnections, the collected data must be merged before analysis. This can be done using the *combine.py* script.

The *analyse.py* file contains code for analyzing the data. This file creates an *analysis.txt* file that provides insights into the collected data.

Before running the scripts, you must specify the names and addresses of the Wi-Fi dongles in the main.py file.

### Disclaimer  
Do not distribute this repository or data without permission from the authors.


### Static Analysis of Firmware Binary: Complete Guide

To perform static analysis on a firmware binary file using a Python script, follow the instructions below. This guide includes prerequisites, installation steps, and usage instructions for the analysis.

---

### **Prerequisites**

Ensure that the following tools are installed on your Linux system:

1. **Binwalk**: A tool for analyzing, reverse engineering, and extracting firmware images.
2. **NumPy**: A Python library used for numerical operations and data manipulation.
3. **Chardet**: A Python library for detecting character encoding.

#### **Installation Commands**:

1. **Install Binwalk**:
   ```bash
   sudo apt-get update
   sudo apt-get install binwalk
   ```

2. **Install NumPy**:
   ```bash
   pip3 install numpy
   ```

3. **Install Chardet**:
   ```bash
   pip3 install chardet
   ```

---

### **Steps for Static Analysis of Firmware Binary**

1. **Organize Files in a Single Directory**:
   - Place both the Python script and the firmware binary file (e.g., `chakravyuh.bin`) in the same directory.

2. **Execute the Python Script**:
   - Open a terminal and run the Python script using the following command:
     ```bash
     python3 <scriptname>.py
     ```

3. **Provide the Path to the Firmware Binary**:
   - When prompted, provide the full file path to the firmware binary, for example:
     ```bash
     /home/usr/Firmware/chakravyuh.bin
     ```
---

By following these steps, you will be able to successfully perform static analysis of the firmware binary using the provided Python script.

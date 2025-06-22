from adafruit_connection_manager import ConnectionManager
import os
from PyP100.PyP110 import P110

#import supervisor; supervisor.set_next_code_file("P110-basic-example.py"); supervisor.reload()

import wifi
radio = wifi.radio  # or supply in a ESP_SPIcontrol or WIZNET5K
if radio.connected:
    print("Connected to the internet")
else:
    print("Not connected to the internet")
    raise Exception("Not connected to the internet")

#   MAC Address	ac:15:a2:46:64:07
# IPv4 Address/Name	192.168.1.161 / P110
# Last Activity	Sun Jun 22 15:40:39 2025
# Status	on
# Allocation	dhcp
# Connection Type	Wi-Fi: free4all

# 	MAC Address	ac:15:a2:46:6c:5f
# IPv4 Address/Name	192.168.1.10 / P110
# Last Activity	Sun Jun 22 15:40:34 2025
# Status	on
# Allocation	dhcp
# Connection Type	Wi-Fi: free4all



# Replace with your device's address, email, and password
address = "192.168.1.161"
email = os.getenv("TAPO_USER")
password = os.getenv("TAPO_KEY")

# Create an instance of the P110 device
p110 = P110(address, email, password, "old", radio=radio)
print("P110 created")

print("Printing device info...")
# Get device information
device_info = p110.getDeviceInfo()
print("Device Info:", device_info)

# Get the device name
device_name = p110.getDeviceName()
print("Device Name:", device_name)

# Turn on the device
print(", turning on...")
p110.turnOn()
print("Device turned on.")


from adafruit_connection_manager import ConnectionManager

from PyP100 import P100

import wifi
radio = wifi.radio  # or supply in a ESP_SPIcontrol or WIZNET5K
if radio.connected:
    print("Connected to the internet")
else:
    print("Not connected to the internet")
    raise Exception("Not connected to the internet")

# Replace with your device's address, email, and password
address = "192.168.50.173"
email = "your_email@example.com"
password = "your_password"

# Create an instance of the P100 device
p100 = P100(address, email, password, radio)

# Turn on the device
p100.turnOn()

# Get device information
device_info = p100.getDeviceInfo()
print("Device Info:", device_info)

# Get the device name
device_name = p100.getDeviceName()
print("Device Name:", device_name)

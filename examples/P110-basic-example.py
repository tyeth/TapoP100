from adafruit_connection_manager import ConnectionManager

from PyP100.PyP110 import P110

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

# Create an instance of the P110 device
p110 = P110(address, email, password, "new", radio=radio)
print("P110 created, turning on...")

# Turn on the device
p110.turnOn()
print("Device turned on. Printing device info...")

# Get device information
device_info = p110.getDeviceInfo()
print("Device Info:", device_info)

# Get the device name
device_name = p110.getDeviceName()
print("Device Name:", device_name)

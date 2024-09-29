import binascii

# Define MeasureInterval since CircuitPython doesn't have the enum module
class MeasureInterval:
    def __init__(self, value):
        self.value = value

MeasureInterval.HOURLY = MeasureInterval('hourly')
MeasureInterval.DAILY = MeasureInterval('daily')
MeasureInterval.MONTHLY = MeasureInterval('monthly')

# Import the AuthProtocol and OldProtocol classes from auth_protocol.py
from auth_protocol import AuthProtocol, OldProtocol

class Device:
    def __init__(self, address, email, password, preferred_protocol=None, **kwargs):
        self.address = address
        self.email = email
        self.password = password
        self.kwargs = kwargs
        self.protocol = None
        self.preferred_protocol = preferred_protocol

    def _initialize(self):
        protocol_classes = {"new": AuthProtocol, "old": OldProtocol}

        # Set preferred protocol if specified
        if self.preferred_protocol and self.preferred_protocol in protocol_classes:
            protocols_to_try = [protocol_classes[self.preferred_protocol]]
        else:
            protocols_to_try = list(protocol_classes.values())

        for protocol_class in protocols_to_try:
            if not self.protocol:
                try:
                    protocol = protocol_class(
                        self.address, self.email, self.password, **self.kwargs
                    )
                    protocol.Initialize()
                    self.protocol = protocol
                except Exception as e:
                    print(
                        f"Failed to initialize protocol {protocol_class.__name__}: {e}"
                    )
        if not self.protocol:
            raise Exception("Failed to initialize protocol")

    def request(self, method, params=None):
        if not self.protocol:
            self._initialize()
        return self.protocol._request(method, params)

    def handshake(self):
        if not self.protocol:
            self._initialize()
        return

    def login(self):
        return self.handshake()

    def getDeviceInfo(self):
        return self.request("get_device_info")

    def _get_device_info(self):
        return self.request("get_device_info")

    def _set_device_info(self, params):
        return self.request("set_device_info", params)

    def getCountDownRules(self):
        return self.request("get_countdown_rules")

    def getDeviceName(self):
        data = self.getDeviceInfo()
        encodedName = data["nickname"]
        # Decode base64 encoded name using binascii
        name_bytes = binascii.a2b_base64(encodedName.encode('utf-8'))
        name = name_bytes.decode("utf-8")
        return name

    def switch_with_delay(self, state, delay):
        return self.request(
            "add_countdown_rule",
            {
                "delay": int(delay),
                "desired_states": {"on": state},
                "enable": True,
                "remain": int(delay),
            },
        )

class Switchable(Device):
    def get_status(self):
        return self._get_device_info()["device_on"]

    def set_status(self, status):
        return self._set_device_info({"device_on": status})

    def turnOn(self):
        return self.set_status(True)

    def turnOff(self):
        return self.set_status(False)

    def toggleState(self):
        current_status = self.get_status()
        return self.set_status(not current_status)

    def turnOnWithDelay(self, delay):
        return self.switch_with_delay(True, delay)

    def turnOffWithDelay(self, delay):
        return self.switch_with_delay(False, delay)

class Metering(Device):
    def getEnergyUsage(self):
        return self.request("get_energy_usage")

    def getEnergyData(self, start_timestamp, end_timestamp, interval):
        """Retrieve energy data within the specified time range and interval."""
        return self.request(
            "get_energy_data",
            {
                "start_timestamp": start_timestamp,
                "end_timestamp": end_timestamp,
                "interval": interval.value,
            },
        )

class Color(Device):
    def setBrightness(self, brightness):
        return self._set_device_info({"brightness": brightness})

    def setColorTemp(self, color_temp):
        return self._set_device_info({"color_temp": color_temp})

    def setColor(self, hue, saturation):
        return self._set_device_info(
            {"color_temp": 0, "hue": hue, "saturation": saturation}
        )

class P100(Switchable):
    pass

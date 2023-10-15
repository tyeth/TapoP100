import logging
from base64 import b64decode
from .auth_protocol import AuthProtocol, OldProtocol

log = logging.getLogger(__name__)


class Device:
    def __init__(self, address, email, password, **kwargs):
        self.address = address
        self.email = email
        self.password = password
        self.kwargs = kwargs
        self.protocol = None

    def _initialize(self):
        for protocol_class in [AuthProtocol, OldProtocol]:
            if not self.protocol:
                try:
                    protocol = protocol_class(
                        self.address, self.email, self.password, **self.kwargs
                    )
                    protocol.Initialize()
                    self.protocol = protocol
                except:
                    log.exception(
                        f"Failed to initialize protocol {protocol_class.__name__}"
                    )
        if not self.protocol:
            raise Exception("Failed to initialize protocol")

    def request(self, method: str, params: dict = None):
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

    def _set_device_info(self, params: dict):
        return self.request("set_device_info", params)

    def getDeviceName(self):
        data = self.getDeviceInfo()
        encodedName = data["nickname"]
        name = b64decode(encodedName)
        return name.decode("utf-8")


class Switchable(Device):
    def get_status(self) -> bool:
        return self._get_device_info()["device_on"]

    def set_status(self, status: bool):
        return self._set_device_info({"device_on": status})

    def turnOn(self):
        return self.set_status(True)

    def turnOff(self):
        return self.set_status(False)

    def toggleState(self):
        return self.set_status(not self.get_status())

    def turnOnWithDelay(self, delay):
        raise NotImplementedError()

    def turnOffWithDelay(self, delay):
        raise NotImplementedError()


class Metering(Device):
    def getEnergyUsage(self) -> dict:
        return self.request("get_energy_usage")


class Color(Device):
    def setBrightness(self, brightness: int):
        return self._set_device_info({"brightness": brightness})

    def setColorTemp(self, color_temp: int):
        return self._set_device_info({"color_temp": color_temp})

    def setColor(self, hue, saturation):
        return self._set_device_info(
            {"color_temp": 0, "hue": hue, "saturation": saturation}
        )


class P100(Switchable):
    pass

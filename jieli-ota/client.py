"""JeiLi OTA client

OTA request

fe dc ba c0 03 00 06 ff ff ff ff ff 00 ef

"""
from time import time, sleep
from random import randbytes
from struct import unpack

from whad.device import WhadDevice
from whad.ble import Central
from whad.ble.profile.attribute import UUID

from auth import ota_auth

class OtaDevice:

    STATE_IDLE = 0
    STATE_AUTH_PHONE_CHALL_SENT = 1
    STATE_AUTH_PHONE_HASH_RECVD = 2
    STATE_AUTH_PHONE_RESULT_SENT = 3
    STATE_AUTH_WATCH_CHALL_RECVD = 4
    STATE_AUTH_WATCH_HASH_SENT = 5
    STATE_AUTH_WATCH_RESULT_RECVD = 6
    STATE_AUTH_WATCH_SUCCEEDED = 7

    STATE_OTA_IDLE = 0
    STATE_OTA_CMD_SENT = 1
    STATE_OTA_RESP_HEADER = 2
    STATE_OTA_RESP_RECVD = 3


    def __init__(self, bdaddr, interface: str = "hci0"):
        """Initialize device
        """
        self.__periph = None
        self.__send = None
        self.__recv = None
        self.__bdaddr = bdaddr
        self.__iface = WhadDevice.create(interface)
        self.__conn = Central(self.__iface)
        self.__connected = False

        # Authentication
        self.__auth_state = OtaDevice.STATE_IDLE
        self.__auth_phone_result = None
        self.__auth_watch_result = None
        self.__auth_watch_challenge = None
        self.__auth_challenge = None

        # OTA Commands
        self.__ota_state = OtaDevice.STATE_OTA_IDLE
        self.__ota_resp = None
        self.__ota_payload_len = 0
        self.__ota_flag = 0
        self.__ota_opcode = 0

    @property
    def authenticated(self) -> bool:
        """Authentication status
        """
        return self.__auth_state == OtaDevice.STATE_AUTH_WATCH_SUCCEEDED

    def __generate_challenge(self) -> bytes:
        """Generate a 16-byte random buffer
        """
        return randbytes(16)

    def connect(self) -> bool:
        """Connect to specified device
        """
        try:
            # Connect to target device
            print(f"Connecting to target device {self.__bdaddr} ...")
            self.__periph = self.__conn.connect(self.__bdaddr)
            print("Connected !")
            self.__connected = True

            # Reset authentication state
            self.__auth_state = OtaDevice.STATE_IDLE

            # Discover services and characteristics
            print("Discovering services and characteristics ...")
            self.__periph.discover()
            print("Done !")

            # Retrieve our "send" and "recv" characteristics
            self.__send = self.__periph.get_characteristic(UUID("AE00"), UUID("AE01"))
            print(f"Send characteristic: {self.__send}")
            self.__recv = self.__periph.get_characteristic(UUID("AE00"), UUID("AE02"))
            print(f"Recv characteristic: {self.__recv}")

            return True
        except Exception:
            return False

    def __on_recv(self, characteristic, value, indication):
        """Process data sent by the smartwatch
        """
        print(f"[ota] Received data: {value.hex()}")

        if not self.authenticated:
            if self.__auth_state == OtaDevice.STATE_AUTH_PHONE_CHALL_SENT:
                # Make sure we received an authentication response from watch
                if value[0] == 1:
                    # Check size and extract response
                    if len(value) == 17:
                        # Extract challenge and check value
                        self.__auth_phone_result = value[1:17] == ota_auth(self.__auth_challenge)
                        
                        # Update state
                        self.__auth_state = OtaDevice.STATE_AUTH_PHONE_HASH_RECVD

                        # Process response
                        self.authenticate()
                    else:
                        # abort authentication
                        print("[step 1] Data size does not match ! Aborting authentication.")
                        self.__auth_state = OtaDevice.STATE_IDLE                        
                else:
                    # abort authentication
                    print("[step 1] Data received is not a challenge response ! Aborting authentication.")
                    self.__auth_state = OtaDevice.STATE_IDLE

            elif self.__auth_state == OtaDevice.STATE_AUTH_PHONE_RESULT_SENT:
                # Make sure we received an authentication request from watch
                if value[0] == 0:
                    # Check size and extract response
                    if len(value) == 17:
                        # Extract challenge and check value
                        self.__auth_watch_challenge = value[1:17]
                        
                        # Update state
                        self.__auth_state = OtaDevice.STATE_AUTH_WATCH_CHALL_RECVD

                        # Process response
                        self.authenticate()
                    else:
                        # abort authentication
                        print("[step 2] Data size does not match ! Aborting authentication.")
                        self.__auth_state = OtaDevice.STATE_IDLE                        
                else:
                    # abort authentication
                    print("[step 2] Data received is not a challenge request ! Aborting authentication.")
                    self.__auth_state = OtaDevice.STATE_IDLE

            elif self.__auth_state == OtaDevice.STATE_AUTH_WATCH_HASH_SENT:
                # Make sure we received an authentication resultfrom watch
                if value[0] == 2:
                    # Check size and extract response
                    if len(value) == 5:
                        # Extract challenge and check value
                        self.__auth_watch_result = b"pass" == value[1:5]
                        
                        # Update state
                        self.__auth_state = OtaDevice.STATE_AUTH_WATCH_RESULT_RECVD

                        # Process response
                        self.authenticate()
                    else:
                        # abort authentication
                        print("[step 4] Data size does not match ! Aborting authentication.")
                        self.__auth_state = OtaDevice.STATE_IDLE                        
                else:
                    # abort authentication
                    print("[step 4] Data received is not a challenge request ! Aborting authentication.")
                    self.__auth_state = OtaDevice.STATE_IDLE
        else:
            # Process OTA response
            if self.__ota_state == OtaDevice.STATE_OTA_CMD_SENT:
                if self.__ota_resp is None:
                    self.__ota_resp = value
                else:
                    self.__ota_resp += value
                
                if len(self.__ota_resp) >= 7:
                    magic, self.__ota_flag, self.__ota_opcode, length = unpack(">3sBBH", value[:7])
                    assert magic == b"\xfe\xdc\xba"
                    self.__ota_payload_len = length + 1
                    self.__ota_resp = value[7:]
                    self.__ota_state = OtaDevice.STATE_OTA_RESP_HEADER

                    if len(self.__ota_resp) >= self.__ota_payload_len:
                        assert self.__ota_resp[-1] == 0xef
                        self.__ota_resp = self.__ota_resp[:-1]
                        self.__ota_state = OtaDevice.STATE_OTA_RESP_RECVD

            elif self.__ota_state == OtaDevice.STATE_OTA_RESP_HEADER:
                self.__ota_resp += value
                print(f"[ota] data: {self.__ota_resp.hex()} ({len(self.__ota_resp)}/{self.__ota_payload_len})")
                if len(self.__ota_resp) >= self.__ota_payload_len:
                    assert self.__ota_resp[-1] == 0xef
                    self.__ota_resp = self.__ota_resp[:-1]
                    self.__ota_state = OtaDevice.STATE_OTA_RESP_RECVD

    def send_data(self, data: bytes) -> bool:
        """Send data to our smartwatch
        """
        self.__send.write(data, without_response=True)


    def authenticate(self) -> bool:
        if self.__connected:

            # Client is idling, start auth process
            # Step 1: send challenge
            if self.__auth_state == OtaDevice.STATE_IDLE:

                # Result auth phone value
                self.__auth_phone_result = None

                # Generate a 16-byte random
                self.__auth_challenge = self.__generate_challenge()

                # Subscribe to a specific characteristic
                self.__recv.subscribe(callback=self.__on_recv)

                # Update state
                self.__auth_state = OtaDevice.STATE_AUTH_PHONE_CHALL_SENT

                # Write to the "send" characteristic
                print("[step 1] Sending challenge to watch")
                self.send_data(bytes([0x00]) + self.__auth_challenge)

                # Success
                return True
            
            # Step 2: process answer from smartwatch
            elif self.__auth_state == OtaDevice.STATE_AUTH_PHONE_HASH_RECVD:
                if not self.__auth_phone_result:
                    # Send fail
                    self.send_data(bytes([0x02]) + b"fail")

                    # Auth failed, abort.
                    self.__auth_state = OtaDevice.STATE_IDLE
                    print("[!] Authentication failed: rejected by watch")
                    self.__auth_phone_result = None
                    return False
                
                # Watch answered correctly
                print("[step 1] Watch successfully authenticated :)")

                # Update state
                self.__auth_state = OtaDevice.STATE_AUTH_PHONE_RESULT_SENT

                # Send answer to watch
                print("[step 2] Send auth result to watch")
                self.send_data(bytes([0x02]) + b"pass")

            # Step 3: process challenge from smartwatch
            elif self.__auth_state == OtaDevice.STATE_AUTH_WATCH_CHALL_RECVD:
                print("[step 3] Received challenge from watch")

                # Reset auth watch result
                self.__auth_watch_result = None
                
                # Compute response
                response = ota_auth(self.__auth_watch_challenge)

                # Update state
                self.__auth_state = OtaDevice.STATE_AUTH_WATCH_HASH_SENT

                # Send response
                print("[step 3] Sending auth response")
                self.send_data(bytes([0x01]) + response)

            # Step 4: process auth response from watch
            elif self.__auth_state == OtaDevice.STATE_AUTH_WATCH_RESULT_RECVD:
                if self.__auth_watch_result:
                    print("[step 4] Authentication successful !")
                    self.__auth_state = OtaDevice.STATE_AUTH_WATCH_SUCCEEDED
                else:
                    print("[step 4] Authentication failed !")
                    self.__auth_state = OtaDevice.STATE_IDLE

    def wait_for_auth(self, timeout: float = 10.0) -> bool:
        """Wait for our authentication process to complete.
        """
        start = time()
        while time() - start < timeout:
            sleep(.1)
            if self.authenticated:
                # Success
                return True
        
        # Failed
        return False

    def send_ota_cmd(self, command: bytes, timeout: float = 10.0) -> bytes:
        """Send an OTA command to our watch
        """
        # Make sure we are authenticated
        if not self.authenticated:
            return False
        
        # Update our state
        self.__ota_state = OtaDevice.STATE_OTA_CMD_SENT

        # Send OTA command to watch
        self.__ota_resp = None
        self.__ota_payload_len = 0
        self.__ota_resp_complete = False
        self.send_data(command)

        # Wait for a response
        start = time()
        while time() - start < timeout:
            if self.__ota_state == OtaDevice.STATE_OTA_RESP_RECVD:
                # Got a response, send it back
                print(f"[ota_cmd] Got response: {self.__ota_resp.hex()}")
                return self.__ota_resp
            
            sleep(.1)
        
        # Timed out
        self.__ota_state = OtaDevice.STATE_OTA_IDLE
        return None

    def get_dev_md5(self) -> bytes:
        """Send a GetDevMD5 command

        fe dc ba c0 d4 00 01 00 ef
        """
        return self.send_ota_cmd(bytes([0xfe, 0xdc, 0xba, 0xc0, 0xd4, 0x00, 0x01, 0x00, 0xef]))

    def disconnect_classic_bt(self):
        return self.send_ota_cmd(bytes([0xfe, 0xdc, 0xba, 0xc0, 0x06,  0x00, 0x01, 0x00, 0xef]))

    def enter_update_mode(self):
        return self.send_ota_cmd(bytes([0xfe, 0xdc, 0xba, 0xc0, 0xe3,  0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0xef]))

    def reboot_device(self):
        return self.send_ota_cmd(bytes([0xfe, 0xdc, 0xba, 0x20, 0xe1, 0x00, 0x02, 0x00, 0x00, 0xef]))
    
    def custom_extra_cmd(self):
        return self.send_ota_cmd(bytes([0xfe, 0xdc, 0xba, 0xc0, 0xf0, 0x00, 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xef]))

dev = OtaDevice("97:ea:e6:b8:a9:b5", "hci1")
dev.connect()
dev.authenticate()
if dev.wait_for_auth():
    # send OTA command
    #response = dev.send_ota_cmd(bytes.fromhex("fedcbac0030006ffffffffff00ef"))
    response = dev.get_dev_md5()
    #response = dev.custom_extra_cmd()
    #response = dev.disconnect_classic_bt()
    print(f"Response: {response.hex()}")
    


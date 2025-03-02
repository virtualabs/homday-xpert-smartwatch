"""JeiLi OTA client

OTA request

fe dc ba c0 03 00 06 ff ff ff ff ff 00 ef

"""
import sys
from crc8dallas import calc
from time import time, sleep
from random import randbytes
from struct import unpack

from whad.device import WhadDevice
from whad.ble import Central
from whad.ble.profile.attribute import UUID

from auth import ota_auth

WATCH_BD_ADDR = "97:ea:e6:b8:a9:b5"
WHAD_IFACE = "hci1"

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

    STATE_UPLOAD_IDLE = 0
    STATE_UPLOAD_SIZE_SENT = 1
    STATE_UPLOAD_DONE = 2


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

        # Upload
        self.__up_state = OtaDevice.STATE_UPLOAD_IDLE
        self.__up_chunks = []
        self.__up_max_index = 0

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

            # Retrieve our lefun send/recv characteristics
            self.__lf_send = self.__periph.get_characteristic(UUID("18D0"), UUID("2D01"))
            self.__lf_recv = self.__periph.get_characteristic(UUID("18D0"), UUID("2D00"))
            self.__lf_recv.subscribe(callback=self.on_lf_recv)

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

    def on_lf_recv(self, characteristic, value, indication):
        """Handle incoming data
        """
        if self.__up_state == self.STATE_UPLOAD_SIZE_SENT:
            print("File size successfully sent, uploading chunks ...")
            for i in range(self.__up_max_index):
                # Let's upload the current chunk
                print(f"Sending chunk {i}/{self.__up_max_index}")
                self.send_chunk(self.__up_chunks[i], i)
            print("Upload complete !")
            self.__up_state = self.STATE_UPLOAD_IDLE

    def send_size(self, size: int):
        """Send the first upload step
        """
        # Prepare our buffer
        nb_packets = (size + 15)//16
        buffer = bytes([0xab, 0x06, 0x28, (nb_packets>>8)&0xff, nb_packets&0xff])
        buffer += bytes([calc(buffer)])

        # Send our buffer
        self.__lf_send.value = buffer

    def send_chunk(self, chunk: bytes, index: int):
        """Send chunk to smartwatch
        """
        assert len(chunk) == 16
        buffer = bytes([0xab, 0x29, (index>>8)&0xff, index&0xff]) + chunk

        # Send our buffer
        self.__lf_send.write(buffer, without_response=True)

    def upload(self, filepath) -> bool:
        """Upload a watch face
        """
        if self.__up_state != self.STATE_UPLOAD_IDLE:
            return False

        print("Reading watchface ...")
        with open(filepath, "rb") as face:
            # Read content
            face_content = face.read()
            face_size = len(face_content)
            print(f"File is {face_size} bytes long")

            # Pad face content
            padlen = len(face_content)%16
            if padlen > 0:
                print(f"add padding ({padlen} bytes for a size of {len(face_content)})")
                face_content += b"\x00"*(16 - padlen)
                face_size = len(face_content)

            # Prepare chunks
            print("Preparing chunks for upload ...")
            self.__up_chunks = []
            self.__up_max_index = face_size//16
            for i in range(self.__up_max_index):
                self.__up_chunks.append(
                    face_content[16*i:16*(i+1)]
                )

            # Upload size
            print("Sending file size ...")
            self.send_size(face_size)
            self.__up_state = self.STATE_UPLOAD_SIZE_SENT


if __name__ == "__main__":
    if len(sys.argv) > 1:
        face_path = sys.argv[1]
        dev = OtaDevice(WATCH_BD_ADDR, WHAD_IFACE)
        dev.connect()
        dev.authenticate()
        if dev.wait_for_auth():
            # Upload watch face !
            dev.upload(face_path)
            input("press a key")
    


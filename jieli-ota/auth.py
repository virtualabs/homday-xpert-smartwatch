"""JeiLi OTA authentication algorithm
"""

from h import H

K = bytes.fromhex("06775f87918dd423005df1d8cf0c142b")

def ota_auth(challenge: bytes) -> bytes:
    """Compute the expected response for the given challenge, based
    on JeiLi's authentication algorithm.

    :param challenge: Challenge
    :type challenge: bytes
    :return: Computed response
    :rtype: bytes
    """
    bdaddr = bytes.fromhex("112233332211")
    _,_,_,_,response = H(bytearray(K), bytearray(challenge), bytearray(bdaddr), 6)

    # Return the computed challenge response
    return response

if __name__ == "__main__":
    response = jl_ota_auth(bytes.fromhex("08e1d0bc75aa4ac8343ca6b142105062"))
    print(f"Response: {response.hex()}")
    expected = bytes.fromhex("5101b7d2e2b497a23e9232f5aa615962")
    print(f"Expected: {expected.hex()}")


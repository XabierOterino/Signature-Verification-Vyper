# @version ^0.3.6

"""
On-chain signature verification:
    1. Hash a message to sign
    2. Sign message hash offchain
    3. verify signature on chain

How to use it:
    1.Call getHash(any_message)
    2.Insert in getEthSignedHash
    3.Get user signature off-chain with the address and the hash as inputs(metamask should work)
    4.Call verify with both signatures and expect to return the off-chain address
"""

@external
@pure
def getHash(_str: String[100]) -> bytes32:
    return keccak256(_str)

@external
@pure
def getEthSignedHash(_hash: bytes32) -> bytes32:
    return keccak256(
        concat(
            b'\x19Ethereum Signed Message\n32',
            _hash
        )
    )


@external
@pure
def verify(_ethSignedHash: bytes32, _sig: Bytes[65]) -> address:
    r: uint256 = convert(slice(_sig,0,32),uint256)# get first 32 bytes of signature and convert to bytes32
    s: uint256 = convert(slice(_sig,32,64),uint256)#from 32 to 64
    v: uint256 = convert(slice(_sig, 64,1), uint256)# from 64 to 1
    return ecrecover(_ethSignedHash, v, r, s) #should return msg.sender 
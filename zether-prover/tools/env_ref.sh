#!/bin/bash
# Independent (foundry cast) reference values for envelope.rs tests.
set -e
TOK=0x1111111111111111111111111111111111111111
FROM=0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
REL=0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
ZERO=0x0000000000000000000000000000000000000000
BATCH=0x0101010101010101010101010101010101010101010101010101010101010101
ENV_TAG=$(cast keccak "SCAAS-ZETHER-ENVELOPE-V1")
echo "binding $(cast keccak $(cast abi-encode 'f(bytes32,uint256,address,address,address,uint256,uint256,uint256,uint256,uint32,address,uint256,address)' $ENV_TAG 31337 $TOK $FROM $ZERO 0 $BATCH 7 1800000000 33 $REL 1000 $ZERO))"
TH=$(cast keccak "MetaTransaction(address from,address to,uint256 value,bytes data,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)")
SH=$(cast keccak $(cast abi-encode 'f(bytes32,address,address,uint256,bytes32,uint256,uint256,uint256,uint32,address,uint256,address)' $TH $FROM $ZERO 0 $(cast keccak 0xdeadbeef) $BATCH 7 1800000000 33 $REL 1000 $ZERO))
DT=$(cast keccak "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
DS=$(cast keccak $(cast abi-encode 'f(bytes32,bytes32,bytes32,uint256,address)' $DT $(cast keccak "SCaaS ZetherToken") $(cast keccak "1") 31337 $TOK))
echo "digest $(cast keccak 0x1901${DS:2}${SH:2})"
echo "transfer_data $(cast calldata 'zetherTransfer(bytes,bytes,bytes,bytes32)' 0xaabb 0xccddee 0x 0x2222222222222222222222222222222222222222222222222222222222222222)"
echo "burn_data $(cast calldata 'zetherBurn(bytes,uint256,address,bytes32,bytes,bytes)' 0xaabb 400000 0x4444444444444444444444444444444444444444 0x0000000000000000000000000000000000000000000000000000000000000000 0xccdd 0x)"
echo "entry_ref $(cast keccak $(cast abi-encode 'f(bytes32,uint256,address,bytes32,uint256)' $(cast keccak SCAAS-ZETHER-ENTRY-V1) 31337 $TOK 0x5555555555555555555555555555555555555555555555555555555555555555 3))"

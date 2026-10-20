#!/bin/bash
# Independent (foundry cast) reference values for the envelope.rs tests (tests/envelope_disclosure.rs).
set -e
TOK=0x1111111111111111111111111111111111111111
CUID=0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464
FROM=0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
REL=0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
ZERO=0x0000000000000000000000000000000000000000
BATCH=0x0101010101010101010101010101010101010101010101010101010101010101
ENV_TAG=$(cast keccak "SCAAS-ZETHER-ENVELOPE-V1")
echo "binding $(cast keccak $(cast abi-encode 'f(bytes32,uint256,bytes32,address,address,bytes32,uint256,uint256,uint32,address,uint256,address)' $ENV_TAG 31337 $CUID $TOK $FROM $BATCH 7 1800000000 33 $REL 1000 $ZERO))"
TH=$(cast keccak "MetaTransaction(address from,bytes data,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)")
SH=$(cast keccak $(cast abi-encode 'f(bytes32,address,bytes32,bytes32,uint256,uint256,uint32,address,uint256,address)' $TH $FROM $(cast keccak 0xdeadbeef) $BATCH 7 1800000000 33 $REL 1000 $ZERO))
DT=$(cast keccak "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)")
DS=$(cast keccak $(cast abi-encode 'f(bytes32,bytes32,bytes32,uint256,address,bytes32)' $DT $(cast keccak "SCaaS ZetherToken") $(cast keccak "1") 31337 $TOK $CUID))
echo "digest $(cast keccak 0x1901${DS:2}${SH:2})"
echo "transfer_call $(cast calldata 'zetherTransferSingle(bytes,bytes,bytes32)' 0xaabb 0xccddee 0x2222222222222222222222222222222222222222222222222222222222222222)"
echo "unshield_call $(cast calldata 'zetherUnshield(bytes,bytes,bytes32,address,uint256)' 0xaabb 0xccdd 0x0000000000000000000000000000000000000000000000000000000000000000 0x4444444444444444444444444444444444444444 400000)"
echo "entry_ref $(cast keccak $(cast abi-encode 'f(bytes32,uint256,bytes32,address,bytes32,uint256)' $(cast keccak SCAAS-ZETHER-ENTRY-V1) 31337 $CUID $TOK 0x5555555555555555555555555555555555555555555555555555555555555555 3))"
echo "unwrap_binding $(cast keccak $(cast abi-encode 'f(bytes32,address,uint256)' $(cast keccak SCAAS-ZETHER-UNWRAP-V1) 0x4444444444444444444444444444444444444444 1000))"
for s in 'zetherTransfer(bytes,bytes,bytes32)' 'zetherTransferSingle(bytes,bytes,bytes32)' 'zetherUnshield(bytes,bytes,bytes32,address,uint256)' 'zetherShield(bytes,uint256)'; do echo "sel $s $(cast sig "$s")"; done

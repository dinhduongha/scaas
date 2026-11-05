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
G=$(printf '%064x' 0)
P="(0x$G,0x$G,0x$G,0x$G)"
B1=0x2222222222222222222222222222222222222222222222222222222222222222
SALT=0x11111111111111111111111111111111
G1T='(bytes32,bytes32,bytes32,bytes32)'
echo "transfer_single_call $(cast calldata "mtxConfidentialTransferSingle((uint64,uint64,uint256,bytes16,bytes32,$G1T,$G1T,$G1T,$G1T,$G1T,$G1T),bytes)" "(5,3,100,$SALT,$B1,$P,$P,$P,$P,$P,$P)" 0xccddee)"
echo "transfer_multi_call $(cast calldata "mtxConfidentialTransfer((uint64,uint64,uint256,bytes16,bytes32,uint256,$G1T,$G1T,$G1T,($G1T,$G1T,$G1T,$G1T)[],bytes),bytes)" "(5,3,100,$SALT,$B1,7,$P,$P,$P,[($P,$P,$P,$P)],0xabcd)" 0xccddee)"
echo "unshield_call $(cast calldata "mtxUnshield((uint64,uint64,uint256,bytes32,$G1T),uint256,bytes32,bytes)" "(5,3,100,0x$G,$P)" 400000 0x0000000000000000000000004444444444444444444444444444444444444444 0xccdd)"
echo "entry_ref $(cast keccak $(cast abi-encode 'f(bytes32,uint256,bytes32,address,bytes32,uint256)' $(cast keccak SCAAS-ZETHER-ENTRY-V1) 31337 $CUID $TOK 0x5555555555555555555555555555555555555555555555555555555555555555 3))"
echo "unwrap_binding $(cast keccak $(cast abi-encode 'f(bytes32,address,uint256)' $(cast keccak SCAAS-ZETHER-UNWRAP-V1) 0x4444444444444444444444444444444444444444 1000))"
for s in 'mtxShield(bytes32,uint256)'; do echo "sel $s $(cast sig "$s")"; done
# ua-mtx-merge T12 (R35, CTR-ZTH-51): the UA binding and the UAMetaTransaction digest of the merged entries, `from` a padded
# native id and a derived id; and one UASig with keyData and members (the last parameter of every merged entry).
UA_TAG=$(cast keccak "SCAAS-ZETHER-UA-ENVELOPE-V1")
UATH=$(cast keccak "UAMetaTransaction(bytes32 from,bytes data,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)")
for UAFROM in 0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 0x7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a; do
  echo "ua_binding $UAFROM $(cast keccak $(cast abi-encode 'f(bytes32,uint256,bytes32,address,bytes32,bytes32,uint256,uint256,uint32,address,uint256,address)' $UA_TAG 31337 $CUID $TOK $UAFROM $BATCH 7 1800000000 33 $REL 1000 $ZERO))"
  USH=$(cast keccak $(cast abi-encode 'f(bytes32,bytes32,bytes32,bytes32,uint256,uint256,uint32,address,uint256,address)' $UATH $UAFROM $(cast keccak 0xdeadbeef) $BATCH 7 1800000000 33 $REL 1000 $ZERO))
  echo "ua_digest $UAFROM $(cast keccak 0x1901${DS:2}${USH:2})"
done
echo "ua_sig $(cast abi-encode 'f((bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]))' '(0xaa,0xbbcc,[(1,[(2,0xdd)],0x),(3,[],0xee)])')"

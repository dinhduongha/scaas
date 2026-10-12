// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
/// SCaaS Universal Account identity layer (accounts.md §1.3-§1.6) in pure Dart; same rules as the Rust, JS, Python,
/// Go and C# libraries (smartcontracts/vectors/ua pins all). Runs on the VM and compiled to JS. UNAUDITED.
library;

export 'src/keydata.dart' show validateKeyData;
export 'src/table.dart' show UAError, Kind, kinds, groups, purposes, kindInfo, isNative, isZether, isSigning, isMember;
export 'src/ua.dart';
export 'src/keccak.dart' show keccak256;

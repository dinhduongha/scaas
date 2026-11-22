package uniffi.scaas_sdk;


public enum FfiConverterTypeSdkError implements FfiConverterRustBuffer<SdkException> {
    INSTANCE;

    @Override
    public SdkException read(java.nio.ByteBuffer buf) {
        return switch(buf.getInt()) {
            case 1 -> new SdkException.Argument(FfiConverterString.INSTANCE.read(buf));
            case 2 -> new SdkException.VaultVersion(FfiConverterString.INSTANCE.read(buf));
            case 3 -> new SdkException.VaultFormat(FfiConverterString.INSTANCE.read(buf));
            case 4 -> new SdkException.VaultIo(FfiConverterString.INSTANCE.read(buf));
            case 5 -> new SdkException.StoreConflict(FfiConverterString.INSTANCE.read(buf));
            case 6 -> new SdkException.KeystoreMismatch(FfiConverterString.INSTANCE.read(buf));
            case 7 -> new SdkException.KeystoreRollback(FfiConverterString.INSTANCE.read(buf));
            case 8 -> new SdkException.AccountUnverified(FfiConverterString.INSTANCE.read(buf));
            case 9 -> new SdkException.SeedUnknown(FfiConverterString.INSTANCE.read(buf));
            case 10 -> new SdkException.SeedExists(FfiConverterString.INSTANCE.read(buf));
            case 11 -> new SdkException.LabelTaken(FfiConverterString.INSTANCE.read(buf));
            case 12 -> new SdkException.ConfirmationMissing(FfiConverterString.INSTANCE.read(buf));
            case 13 -> new SdkException.MnemonicInvalid(FfiConverterString.INSTANCE.read(buf));
            case 14 -> new SdkException.VaultPassphraseWeak(FfiConverterString.INSTANCE.read(buf));
            case 15 -> new SdkException.DerivationPassphraseShort(FfiConverterString.INSTANCE.read(buf));
            case 16 -> new SdkException.OriginSignature(FfiConverterString.INSTANCE.read(buf));
            case 17 -> new SdkException.AuthenticatorRefused(FfiConverterString.INSTANCE.read(buf));
            case 18 -> new SdkException.ChainUnknown(FfiConverterString.INSTANCE.read(buf));
            case 19 -> new SdkException.ProfileMismatch(FfiConverterString.INSTANCE.read(buf));
            case 20 -> new SdkException.FeatureMissing(FfiConverterString.INSTANCE.read(buf));
            case 21 -> new SdkException.PreparedStale(FfiConverterString.INSTANCE.read(buf));
            case 22 -> new SdkException.PreparedUnknown(FfiConverterString.INSTANCE.read(buf));
            case 23 -> new SdkException.OpaqueCallRefused(FfiConverterString.INSTANCE.read(buf));
            case 24 -> new SdkException.FeeAboveCap(FfiConverterString.INSTANCE.read(buf));
            case 25 -> new SdkException.GasAboveTxCap(FfiConverterString.INSTANCE.read(buf));
            case 26 -> new SdkException.PayerDelegated(FfiConverterString.INSTANCE.read(buf));
            case 27 -> new SdkException.SubmitPathNone(FfiConverterString.INSTANCE.read(buf));
            case 28 -> new SdkException.VerdictRefused(FfiConverterString.INSTANCE.read(buf));
            case 29 -> new SdkException.TxTypeRefused(FfiConverterString.INSTANCE.read(buf));
            case 30 -> new SdkException.KindDisabled(FfiConverterString.INSTANCE.read(buf));
            case 31 -> new SdkException.RawDigestRefused(FfiConverterString.INSTANCE.read(buf));
            case 32 -> new SdkException.AppDomainRefused(FfiConverterString.INSTANCE.read(buf));
            case 33 -> new SdkException.AppPurposeRefused(FfiConverterString.INSTANCE.read(buf));
            case 34 -> new SdkException.AppSaltMismatch(FfiConverterString.INSTANCE.read(buf));
            case 35 -> new SdkException.AppHandleForeign(FfiConverterString.INSTANCE.read(buf));
            case 36 -> new SdkException.AppLabelRefused(FfiConverterString.INSTANCE.read(buf));
            case 37 -> new SdkException.AppKeyUsage(FfiConverterString.INSTANCE.read(buf));
            case 38 -> new SdkException.AppArenaFull(FfiConverterString.INSTANCE.read(buf));
            case 39 -> new SdkException.KemKeyGone(FfiConverterString.INSTANCE.read(buf));
            case 40 -> new SdkException.ReceiverUnregistered(FfiConverterString.INSTANCE.read(buf));
            case 41 -> new SdkException.RegistrationUaMismatch(FfiConverterString.INSTANCE.read(buf));
            case 42 -> new SdkException.RegistrationKindDisabled(FfiConverterString.INSTANCE.read(buf));
            case 43 -> new SdkException.RegistrationPopInvalid(FfiConverterString.INSTANCE.read(buf));
            case 44 -> new SdkException.RegistrationKemMissing(FfiConverterString.INSTANCE.read(buf));
            case 45 -> new SdkException.AbiMismatch(FfiConverterString.INSTANCE.read(buf));
            case 46 -> new SdkException.Internal(FfiConverterString.INSTANCE.read(buf));
            case 47 -> new SdkException.AccountExists(FfiConverterString.INSTANCE.read(buf));
            case 48 -> new SdkException.GasUnquoted(FfiConverterString.INSTANCE.read(buf));
            case 49 -> new SdkException.ValidUntilRefused(FfiConverterString.INSTANCE.read(buf));
            case 50 -> new SdkException.TokenUncatalogued(FfiConverterString.INSTANCE.read(buf));
            case 51 -> new SdkException.LegKeyMismatch(FfiConverterString.INSTANCE.read(buf));
            case 52 -> new SdkException.SignerNotAccountKey(FfiConverterString.INSTANCE.read(buf));
            case 53 -> new SdkException.PqzOpeningUnsupported(FfiConverterString.INSTANCE.read(buf));
            case 54 -> new SdkException.MsigSlotInactive(FfiConverterString.INSTANCE.read(buf));
            case 55 -> new SdkException.GasSigBytesMissing(FfiConverterString.INSTANCE.read(buf));
            case 56 -> new SdkException.SignedGasAboveCap(FfiConverterString.INSTANCE.read(buf));
            case 57 -> new SdkException.GasItemUnpaired(FfiConverterString.INSTANCE.read(buf));
            case 58 -> new SdkException.GasItemUnknown(FfiConverterString.INSTANCE.read(buf));
            case 59 -> new SdkException.GasCountUnknown(FfiConverterString.INSTANCE.read(buf));
            case 60 -> new SdkException.BlsMultiBelowThreshold(FfiConverterString.INSTANCE.read(buf));
            case 61 -> new SdkException.GasFieldUnknown(FfiConverterString.INSTANCE.read(buf));
            case 62 -> new SdkException.RegistrationVerifyOnly(FfiConverterString.INSTANCE.read(buf));
            case 63 -> new SdkException.UaUnregistered(FfiConverterString.INSTANCE.read(buf));
            case 64 -> new SdkException.PqzHomeNone(FfiConverterString.INSTANCE.read(buf));
            case 65 -> new SdkException.DexNotListed(FfiConverterString.INSTANCE.read(buf));
            case 66 -> new SdkException.PqzAuditorNative(FfiConverterString.INSTANCE.read(buf));
            case 67 -> new SdkException.GasAboveBlockShare(FfiConverterString.INSTANCE.read(buf));
            case 68 -> new SdkException.ImportKindRefused(FfiConverterString.INSTANCE.read(buf));
            case 69 -> new SdkException.ImportNotPayee(FfiConverterString.INSTANCE.read(buf));
            case 70 -> new SdkException.ImportRelayerBound(FfiConverterString.INSTANCE.read(buf));
            case 71 -> new SdkException.ImportFeeRefused(FfiConverterString.INSTANCE.read(buf));
            case 72 -> new SdkException.ImportExpired(FfiConverterString.INSTANCE.read(buf));
            case 73 -> new SdkException.ImportConsumed(FfiConverterString.INSTANCE.read(buf));
            case 74 -> new SdkException.ImportedOpRefused(FfiConverterString.INSTANCE.read(buf));
            case 75 -> new SdkException.PayerUnavailable(FfiConverterString.INSTANCE.read(buf));
            case 76 -> new SdkException.PaymentRequired(FfiConverterString.INSTANCE.read(buf));
            case 77 -> new SdkException.UploadRejected(FfiConverterString.INSTANCE.read(buf));
            case 78 -> new SdkException.UploadUnsettled(FfiConverterString.INSTANCE.read(buf));
            case 79 -> new SdkException.ArweaveItem(FfiConverterString.INSTANCE.read(buf));
            case 80 -> new SdkException.FileTooLarge(FfiConverterString.INSTANCE.read(buf));
            case 81 -> new SdkException.FileHashMismatch(FfiConverterString.INSTANCE.read(buf));
            case 82 -> new SdkException.Cancelled(FfiConverterString.INSTANCE.read(buf));
            case 83 -> new SdkException.Ua(FfiConverterString.INSTANCE.read(buf));
            case 84 -> new SdkException.Rpc(FfiConverterString.INSTANCE.read(buf));
            default -> throw new java.lang.RuntimeException("invalid error enum value, something is very wrong!!");
        };
    }

    @Override
    public long allocationSize(SdkException value) {
        return 4L;
    }

    @Override
    public void write(SdkException value, java.nio.ByteBuffer buf) {
        switch(value) {
            case SdkException.Argument x -> {
                buf.putInt(1);
            }
            case SdkException.VaultVersion x -> {
                buf.putInt(2);
            }
            case SdkException.VaultFormat x -> {
                buf.putInt(3);
            }
            case SdkException.VaultIo x -> {
                buf.putInt(4);
            }
            case SdkException.StoreConflict x -> {
                buf.putInt(5);
            }
            case SdkException.KeystoreMismatch x -> {
                buf.putInt(6);
            }
            case SdkException.KeystoreRollback x -> {
                buf.putInt(7);
            }
            case SdkException.AccountUnverified x -> {
                buf.putInt(8);
            }
            case SdkException.SeedUnknown x -> {
                buf.putInt(9);
            }
            case SdkException.SeedExists x -> {
                buf.putInt(10);
            }
            case SdkException.LabelTaken x -> {
                buf.putInt(11);
            }
            case SdkException.ConfirmationMissing x -> {
                buf.putInt(12);
            }
            case SdkException.MnemonicInvalid x -> {
                buf.putInt(13);
            }
            case SdkException.VaultPassphraseWeak x -> {
                buf.putInt(14);
            }
            case SdkException.DerivationPassphraseShort x -> {
                buf.putInt(15);
            }
            case SdkException.OriginSignature x -> {
                buf.putInt(16);
            }
            case SdkException.AuthenticatorRefused x -> {
                buf.putInt(17);
            }
            case SdkException.ChainUnknown x -> {
                buf.putInt(18);
            }
            case SdkException.ProfileMismatch x -> {
                buf.putInt(19);
            }
            case SdkException.FeatureMissing x -> {
                buf.putInt(20);
            }
            case SdkException.PreparedStale x -> {
                buf.putInt(21);
            }
            case SdkException.PreparedUnknown x -> {
                buf.putInt(22);
            }
            case SdkException.OpaqueCallRefused x -> {
                buf.putInt(23);
            }
            case SdkException.FeeAboveCap x -> {
                buf.putInt(24);
            }
            case SdkException.GasAboveTxCap x -> {
                buf.putInt(25);
            }
            case SdkException.PayerDelegated x -> {
                buf.putInt(26);
            }
            case SdkException.SubmitPathNone x -> {
                buf.putInt(27);
            }
            case SdkException.VerdictRefused x -> {
                buf.putInt(28);
            }
            case SdkException.TxTypeRefused x -> {
                buf.putInt(29);
            }
            case SdkException.KindDisabled x -> {
                buf.putInt(30);
            }
            case SdkException.RawDigestRefused x -> {
                buf.putInt(31);
            }
            case SdkException.AppDomainRefused x -> {
                buf.putInt(32);
            }
            case SdkException.AppPurposeRefused x -> {
                buf.putInt(33);
            }
            case SdkException.AppSaltMismatch x -> {
                buf.putInt(34);
            }
            case SdkException.AppHandleForeign x -> {
                buf.putInt(35);
            }
            case SdkException.AppLabelRefused x -> {
                buf.putInt(36);
            }
            case SdkException.AppKeyUsage x -> {
                buf.putInt(37);
            }
            case SdkException.AppArenaFull x -> {
                buf.putInt(38);
            }
            case SdkException.KemKeyGone x -> {
                buf.putInt(39);
            }
            case SdkException.ReceiverUnregistered x -> {
                buf.putInt(40);
            }
            case SdkException.RegistrationUaMismatch x -> {
                buf.putInt(41);
            }
            case SdkException.RegistrationKindDisabled x -> {
                buf.putInt(42);
            }
            case SdkException.RegistrationPopInvalid x -> {
                buf.putInt(43);
            }
            case SdkException.RegistrationKemMissing x -> {
                buf.putInt(44);
            }
            case SdkException.AbiMismatch x -> {
                buf.putInt(45);
            }
            case SdkException.Internal x -> {
                buf.putInt(46);
            }
            case SdkException.AccountExists x -> {
                buf.putInt(47);
            }
            case SdkException.GasUnquoted x -> {
                buf.putInt(48);
            }
            case SdkException.ValidUntilRefused x -> {
                buf.putInt(49);
            }
            case SdkException.TokenUncatalogued x -> {
                buf.putInt(50);
            }
            case SdkException.LegKeyMismatch x -> {
                buf.putInt(51);
            }
            case SdkException.SignerNotAccountKey x -> {
                buf.putInt(52);
            }
            case SdkException.PqzOpeningUnsupported x -> {
                buf.putInt(53);
            }
            case SdkException.MsigSlotInactive x -> {
                buf.putInt(54);
            }
            case SdkException.GasSigBytesMissing x -> {
                buf.putInt(55);
            }
            case SdkException.SignedGasAboveCap x -> {
                buf.putInt(56);
            }
            case SdkException.GasItemUnpaired x -> {
                buf.putInt(57);
            }
            case SdkException.GasItemUnknown x -> {
                buf.putInt(58);
            }
            case SdkException.GasCountUnknown x -> {
                buf.putInt(59);
            }
            case SdkException.BlsMultiBelowThreshold x -> {
                buf.putInt(60);
            }
            case SdkException.GasFieldUnknown x -> {
                buf.putInt(61);
            }
            case SdkException.RegistrationVerifyOnly x -> {
                buf.putInt(62);
            }
            case SdkException.UaUnregistered x -> {
                buf.putInt(63);
            }
            case SdkException.PqzHomeNone x -> {
                buf.putInt(64);
            }
            case SdkException.DexNotListed x -> {
                buf.putInt(65);
            }
            case SdkException.PqzAuditorNative x -> {
                buf.putInt(66);
            }
            case SdkException.GasAboveBlockShare x -> {
                buf.putInt(67);
            }
            case SdkException.ImportKindRefused x -> {
                buf.putInt(68);
            }
            case SdkException.ImportNotPayee x -> {
                buf.putInt(69);
            }
            case SdkException.ImportRelayerBound x -> {
                buf.putInt(70);
            }
            case SdkException.ImportFeeRefused x -> {
                buf.putInt(71);
            }
            case SdkException.ImportExpired x -> {
                buf.putInt(72);
            }
            case SdkException.ImportConsumed x -> {
                buf.putInt(73);
            }
            case SdkException.ImportedOpRefused x -> {
                buf.putInt(74);
            }
            case SdkException.PayerUnavailable x -> {
                buf.putInt(75);
            }
            case SdkException.PaymentRequired x -> {
                buf.putInt(76);
            }
            case SdkException.UploadRejected x -> {
                buf.putInt(77);
            }
            case SdkException.UploadUnsettled x -> {
                buf.putInt(78);
            }
            case SdkException.ArweaveItem x -> {
                buf.putInt(79);
            }
            case SdkException.FileTooLarge x -> {
                buf.putInt(80);
            }
            case SdkException.FileHashMismatch x -> {
                buf.putInt(81);
            }
            case SdkException.Cancelled x -> {
                buf.putInt(82);
            }
            case SdkException.Ua x -> {
                buf.putInt(83);
            }
            case SdkException.Rpc x -> {
                buf.putInt(84);
            }
            default -> throw new java.lang.RuntimeException("invalid error enum value, something is very wrong!!");
        };
    }
}




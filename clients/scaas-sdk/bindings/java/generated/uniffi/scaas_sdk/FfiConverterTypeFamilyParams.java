package uniffi.scaas_sdk;


public enum FfiConverterTypeFamilyParams implements FfiConverterRustBuffer<FamilyParams> {
    INSTANCE;

    @Override
    public FamilyParams read(java.nio.ByteBuffer buf) {
      return switch (buf.getInt()) {
        case 1 -> new FamilyParams.Cosmos(FfiConverterString.INSTANCE.read(buf),
          FfiConverterSequenceTypeEndpointConfig.INSTANCE.read(buf),
          FfiConverterTypePolicy.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf)
          );
        case 2 -> new FamilyParams.Aptos(FfiConverterByte.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf)
          );
        case 3 -> new FamilyParams.Solana(FfiConverterString.INSTANCE.read(buf)
          );
        case 4 -> new FamilyParams.Soroban(FfiConverterString.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf)
          );
        case 5 -> new FamilyParams.Sui(FfiConverterSequenceTypeEndpointConfig.INSTANCE.read(buf),
          FfiConverterTypePolicy.INSTANCE.read(buf)
          );
        case 6 -> new FamilyParams.Substrate(FfiConverterSequenceTypeEndpointConfig.INSTANCE.read(buf),
          FfiConverterTypePolicy.INSTANCE.read(buf),
          FfiConverterString.INSTANCE.read(buf),
          FfiConverterShort.INSTANCE.read(buf)
          );
        default ->
          throw new java.lang.RuntimeException("invalid enum value, something is very wrong!");
      };
    }

    @Override
    public long allocationSize(FamilyParams value) {
        return switch (value) {
          case FamilyParams.Cosmos(var chainId, var rest, var restPolicy, var denom, var prefix) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(chainId)
            + FfiConverterSequenceTypeEndpointConfig.INSTANCE.allocationSize(rest)
            + FfiConverterTypePolicy.INSTANCE.allocationSize(restPolicy)
            + FfiConverterString.INSTANCE.allocationSize(denom)
            + FfiConverterString.INSTANCE.allocationSize(prefix));
          case FamilyParams.Aptos(var chainId, var _package) ->
            (4L
            + FfiConverterByte.INSTANCE.allocationSize(chainId)
            + FfiConverterString.INSTANCE.allocationSize(_package));
          case FamilyParams.Solana(var program) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(program));
          case FamilyParams.Soroban(var passphrase, var xlmSac) ->
            (4L
            + FfiConverterString.INSTANCE.allocationSize(passphrase)
            + FfiConverterString.INSTANCE.allocationSize(xlmSac));
          case FamilyParams.Sui(var graphql, var graphqlPolicy) ->
            (4L
            + FfiConverterSequenceTypeEndpointConfig.INSTANCE.allocationSize(graphql)
            + FfiConverterTypePolicy.INSTANCE.allocationSize(graphqlPolicy));
          case FamilyParams.Substrate(var rpc, var rpcPolicy, var genesis, var ss58Prefix) ->
            (4L
            + FfiConverterSequenceTypeEndpointConfig.INSTANCE.allocationSize(rpc)
            + FfiConverterTypePolicy.INSTANCE.allocationSize(rpcPolicy)
            + FfiConverterString.INSTANCE.allocationSize(genesis)
            + FfiConverterShort.INSTANCE.allocationSize(ss58Prefix));
        };
    }

    @Override
    public void write(FamilyParams value, java.nio.ByteBuffer buf) {
      switch (value) {
        case FamilyParams.Cosmos(var chainId, var rest, var restPolicy, var denom, var prefix) -> {
          buf.putInt(1);
          FfiConverterString.INSTANCE.write(chainId, buf);
          FfiConverterSequenceTypeEndpointConfig.INSTANCE.write(rest, buf);
          FfiConverterTypePolicy.INSTANCE.write(restPolicy, buf);
          FfiConverterString.INSTANCE.write(denom, buf);
          FfiConverterString.INSTANCE.write(prefix, buf);
        }
        case FamilyParams.Aptos(var chainId, var _package) -> {
          buf.putInt(2);
          FfiConverterByte.INSTANCE.write(chainId, buf);
          FfiConverterString.INSTANCE.write(_package, buf);
        }
        case FamilyParams.Solana(var program) -> {
          buf.putInt(3);
          FfiConverterString.INSTANCE.write(program, buf);
        }
        case FamilyParams.Soroban(var passphrase, var xlmSac) -> {
          buf.putInt(4);
          FfiConverterString.INSTANCE.write(passphrase, buf);
          FfiConverterString.INSTANCE.write(xlmSac, buf);
        }
        case FamilyParams.Sui(var graphql, var graphqlPolicy) -> {
          buf.putInt(5);
          FfiConverterSequenceTypeEndpointConfig.INSTANCE.write(graphql, buf);
          FfiConverterTypePolicy.INSTANCE.write(graphqlPolicy, buf);
        }
        case FamilyParams.Substrate(var rpc, var rpcPolicy, var genesis, var ss58Prefix) -> {
          buf.putInt(6);
          FfiConverterSequenceTypeEndpointConfig.INSTANCE.write(rpc, buf);
          FfiConverterTypePolicy.INSTANCE.write(rpcPolicy, buf);
          FfiConverterString.INSTANCE.write(genesis, buf);
          FfiConverterShort.INSTANCE.write(ss58Prefix, buf);
        }
      };
    }
}






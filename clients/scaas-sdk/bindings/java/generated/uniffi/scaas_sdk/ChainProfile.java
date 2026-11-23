package uniffi.scaas_sdk;

/**
 * A chain as the app's release pins it (spec §4).
 */
public class ChainProfile {
    /**
     * `scaas-testnet`, `<chain>-mainnet`, `<chain>-testnet`
     */
    private java.lang.String key;
    private Family family;
    /**
     * EVM and Hedera
     */
    private java.lang.Long chainId;
    /**
     * `0x` + 64 hex (NET-ALL-24): every SCaaS EIP-712 domain's salt, pinned on every connection
     */
    private java.lang.String chainUid;
    private java.util.List<EndpointConfig> rpc;
    private Policy rpcPolicy;
    /**
     * scaas-node gateways; empty: no gateway path on this chain
     */
    private java.util.List<EndpointConfig> gateways;
    private java.lang.String registry;
    private java.lang.String factory;
    private java.lang.String router;
    private Finality finality;
    /**
     * the chain's per-transaction cap of the **regular** gas (EIP-7825 on a chain applying EIP-8037) when it has one, from
     * the release data: a quote's regular bound is held to it, its gas limit (regular + state) to the block gas limit. A
     * chain capping the whole gas limit (EIP-7825 without EIP-8037) is not supported (merged-tree review M19, 2026-11-20)
     */
    private java.lang.Long txGasCap;
    /**
     * the reviewed token list (spec §8.2): a token not on it is `unlisted` wherever it is shown
     */
    private java.util.List<ListedToken> tokens;
    /**
     * gas figures measured on this chain, shipped with its release data (owner 2026-11-19, gas-table rulings; spec §13.3);
     * first in every lookup, base and verify each on its own
     */
    private GasRows gas;
    /**
     * the further gas tables this chain uses, by name, only because it names them here (explicit opt-in): module tables of
     * [`SdkConfig::gas_tables`] in this order, and `"reference"` for the SDK's forge-generated reference table, read after
     * every module table; a name the SDK does not hold is `Argument` at `Sdk::open`
     */
    private java.util.List<java.lang.String> gasOptIn;
    /**
     * the longest an operation's `validUntil` may lie ahead of the SDK's clock on this chain, in seconds; `None`:
     * `Limits::max_valid_secs` (default 86 400, one day) (owner 2026-11-19, T13b ruling 1)
     */
    private java.lang.Long maxValidSecs;
    /**
     * the PQZ verifiers a verifier-mode token's verdict is asked of (spec §9.3): a list of endpoints with its own policy,
     * `failover` (the default) or `strict_majority` (ARCH-POS-15; owner 2026-11-19, T16-a), each with its own credential;
     * empty: no verdict on this chain (`VerdictRefused`)
     */
    private java.util.List<EndpointConfig> verifiers;
    private Policy verifierPolicy;
    /**
     * the SCaaS DEXes of the chain (NET-ALL-24): an order or a cancel naming a DEX not here is refused before anything is
     * signed (CLI-SGN-35, `DexNotListed`)
     */
    private java.util.List<ListedDex> dexes;
    /**
     * the reviewed wrapped tokens a `UAWrapOrder` may mint (`Expect::WrapOrder`'s list; `DexNotListed` for another)
     */
    private java.util.List<java.lang.String> wrappers;
    /**
     * the family data a non-EVM read needs beyond the fields above (spec §8.7 rule 2), release data as the rest; `None` on a
     * family that needs none. Params of another family than `family`, or a field out of its form, are `Argument` at
     * `Sdk::open`
     */
    private FamilyParams familyParams;
    /**
     * the chain's L1 data fee model of a self-relay quote (plan T38, spec §27.3; T26 B2-1): `OpStack` on Base, Celo and OP
     * (the node's `params.l1_fee = "op-stack"`), added to `max_cost`; `InEstimate` on Arbitrum, in the gas limit; `Linea` on
     * Linea, in the fees; `None`: no L1 fee and no L1 read. EVM profiles only (`Argument` at
     * `Sdk::open` on another family)
     */
    private L1Fee l1Fee;
    /**
     * the kinds this chain cannot carry, disabled by the owner (2026-11-22, ARCH-POS-18 confirmed: OP, Arbitrum, Base mainnet
     * and Celo, the kinds whose largest transaction is above the chain's limit): a UA kind by its name (`mldsa65`), the PQZ token and key
     * attachment as `pqz`; an operation signed by such a kind, a registration of it, a PQZ operation or attachment is
     * `KindDisabled` before anything is signed. A name the SDK does not know is `Argument` at `Sdk::open`
     */
    private java.util.List<java.lang.String> disabledKinds;
    /**
     * Whether the chain's RPC is trusted on a read pinned by block hash (owner 2026-11-22, decisions ARCH-POS-20 (2); the
     * profile's `pinnedReads`, default true): false on Moonbeam and Moonbase, whose RPC answers a read pinned by a made-up
     * hash. With false, every pinned read (CLI-RPC-05: a decisive read, a read feeding a decryption) is refused by name,
     * `PinnedReadsUntrusted`; plain reads work. EVM profiles only (`Argument` at `Sdk::open` on another family)
     */
    private boolean pinnedReads;

    public ChainProfile(
        java.lang.String key, 
        Family family, 
        java.lang.Long chainId, 
        java.lang.String chainUid, 
        java.util.List<EndpointConfig> rpc, 
        Policy rpcPolicy, 
        java.util.List<EndpointConfig> gateways, 
        java.lang.String registry, 
        java.lang.String factory, 
        java.lang.String router, 
        Finality finality, 
        java.lang.Long txGasCap, 
        java.util.List<ListedToken> tokens, 
        GasRows gas, 
        java.util.List<java.lang.String> gasOptIn, 
        java.lang.Long maxValidSecs, 
        java.util.List<EndpointConfig> verifiers, 
        Policy verifierPolicy, 
        java.util.List<ListedDex> dexes, 
        java.util.List<java.lang.String> wrappers, 
        FamilyParams familyParams, 
        L1Fee l1Fee, 
        java.util.List<java.lang.String> disabledKinds, 
        boolean pinnedReads
    ) {
        
        this.key = key;
        
        this.family = family;
        
        this.chainId = chainId;
        
        this.chainUid = chainUid;
        
        this.rpc = rpc;
        
        this.rpcPolicy = rpcPolicy;
        
        this.gateways = gateways;
        
        this.registry = registry;
        
        this.factory = factory;
        
        this.router = router;
        
        this.finality = finality;
        
        this.txGasCap = txGasCap;
        
        this.tokens = tokens;
        
        this.gas = gas;
        
        this.gasOptIn = gasOptIn;
        
        this.maxValidSecs = maxValidSecs;
        
        this.verifiers = verifiers;
        
        this.verifierPolicy = verifierPolicy;
        
        this.dexes = dexes;
        
        this.wrappers = wrappers;
        
        this.familyParams = familyParams;
        
        this.l1Fee = l1Fee;
        
        this.disabledKinds = disabledKinds;
        
        this.pinnedReads = pinnedReads;
    }
    
    public java.lang.String key() {
        return this.key;
    }
    
    public Family family() {
        return this.family;
    }
    
    public java.lang.Long chainId() {
        return this.chainId;
    }
    
    public java.lang.String chainUid() {
        return this.chainUid;
    }
    
    public java.util.List<EndpointConfig> rpc() {
        return this.rpc;
    }
    
    public Policy rpcPolicy() {
        return this.rpcPolicy;
    }
    
    public java.util.List<EndpointConfig> gateways() {
        return this.gateways;
    }
    
    public java.lang.String registry() {
        return this.registry;
    }
    
    public java.lang.String factory() {
        return this.factory;
    }
    
    public java.lang.String router() {
        return this.router;
    }
    
    public Finality finality() {
        return this.finality;
    }
    
    public java.lang.Long txGasCap() {
        return this.txGasCap;
    }
    
    public java.util.List<ListedToken> tokens() {
        return this.tokens;
    }
    
    public GasRows gas() {
        return this.gas;
    }
    
    public java.util.List<java.lang.String> gasOptIn() {
        return this.gasOptIn;
    }
    
    public java.lang.Long maxValidSecs() {
        return this.maxValidSecs;
    }
    
    public java.util.List<EndpointConfig> verifiers() {
        return this.verifiers;
    }
    
    public Policy verifierPolicy() {
        return this.verifierPolicy;
    }
    
    public java.util.List<ListedDex> dexes() {
        return this.dexes;
    }
    
    public java.util.List<java.lang.String> wrappers() {
        return this.wrappers;
    }
    
    public FamilyParams familyParams() {
        return this.familyParams;
    }
    
    public L1Fee l1Fee() {
        return this.l1Fee;
    }
    
    public java.util.List<java.lang.String> disabledKinds() {
        return this.disabledKinds;
    }
    
    public boolean pinnedReads() {
        return this.pinnedReads;
    }
    public void setKey(java.lang.String key) {
        this.key = key;
    }
    public void setFamily(Family family) {
        this.family = family;
    }
    public void setChainId(java.lang.Long chainId) {
        this.chainId = chainId;
    }
    public void setChainUid(java.lang.String chainUid) {
        this.chainUid = chainUid;
    }
    public void setRpc(java.util.List<EndpointConfig> rpc) {
        this.rpc = rpc;
    }
    public void setRpcPolicy(Policy rpcPolicy) {
        this.rpcPolicy = rpcPolicy;
    }
    public void setGateways(java.util.List<EndpointConfig> gateways) {
        this.gateways = gateways;
    }
    public void setRegistry(java.lang.String registry) {
        this.registry = registry;
    }
    public void setFactory(java.lang.String factory) {
        this.factory = factory;
    }
    public void setRouter(java.lang.String router) {
        this.router = router;
    }
    public void setFinality(Finality finality) {
        this.finality = finality;
    }
    public void setTxGasCap(java.lang.Long txGasCap) {
        this.txGasCap = txGasCap;
    }
    public void setTokens(java.util.List<ListedToken> tokens) {
        this.tokens = tokens;
    }
    public void setGas(GasRows gas) {
        this.gas = gas;
    }
    public void setGasOptIn(java.util.List<java.lang.String> gasOptIn) {
        this.gasOptIn = gasOptIn;
    }
    public void setMaxValidSecs(java.lang.Long maxValidSecs) {
        this.maxValidSecs = maxValidSecs;
    }
    public void setVerifiers(java.util.List<EndpointConfig> verifiers) {
        this.verifiers = verifiers;
    }
    public void setVerifierPolicy(Policy verifierPolicy) {
        this.verifierPolicy = verifierPolicy;
    }
    public void setDexes(java.util.List<ListedDex> dexes) {
        this.dexes = dexes;
    }
    public void setWrappers(java.util.List<java.lang.String> wrappers) {
        this.wrappers = wrappers;
    }
    public void setFamilyParams(FamilyParams familyParams) {
        this.familyParams = familyParams;
    }
    public void setL1Fee(L1Fee l1Fee) {
        this.l1Fee = l1Fee;
    }
    public void setDisabledKinds(java.util.List<java.lang.String> disabledKinds) {
        this.disabledKinds = disabledKinds;
    }
    public void setPinnedReads(boolean pinnedReads) {
        this.pinnedReads = pinnedReads;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof ChainProfile) {
            ChainProfile t = (ChainProfile) other;
            return (
              java.util.Objects.equals(key, t.key) && 
              
              java.util.Objects.equals(family, t.family) && 
              
              java.util.Objects.equals(chainId, t.chainId) && 
              
              java.util.Objects.equals(chainUid, t.chainUid) && 
              
              java.util.Objects.equals(rpc, t.rpc) && 
              
              java.util.Objects.equals(rpcPolicy, t.rpcPolicy) && 
              
              java.util.Objects.equals(gateways, t.gateways) && 
              
              java.util.Objects.equals(registry, t.registry) && 
              
              java.util.Objects.equals(factory, t.factory) && 
              
              java.util.Objects.equals(router, t.router) && 
              
              java.util.Objects.equals(finality, t.finality) && 
              
              java.util.Objects.equals(txGasCap, t.txGasCap) && 
              
              java.util.Objects.equals(tokens, t.tokens) && 
              
              java.util.Objects.equals(gas, t.gas) && 
              
              java.util.Objects.equals(gasOptIn, t.gasOptIn) && 
              
              java.util.Objects.equals(maxValidSecs, t.maxValidSecs) && 
              
              java.util.Objects.equals(verifiers, t.verifiers) && 
              
              java.util.Objects.equals(verifierPolicy, t.verifierPolicy) && 
              
              java.util.Objects.equals(dexes, t.dexes) && 
              
              java.util.Objects.equals(wrappers, t.wrappers) && 
              
              java.util.Objects.equals(familyParams, t.familyParams) && 
              
              java.util.Objects.equals(l1Fee, t.l1Fee) && 
              
              java.util.Objects.equals(disabledKinds, t.disabledKinds) && 
              
              pinnedReads == t.pinnedReads
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(key);
        result = 31 * result + java.util.Objects.hashCode(family);
        result = 31 * result + java.util.Objects.hashCode(chainId);
        result = 31 * result + java.util.Objects.hashCode(chainUid);
        result = 31 * result + java.util.Objects.hashCode(rpc);
        result = 31 * result + java.util.Objects.hashCode(rpcPolicy);
        result = 31 * result + java.util.Objects.hashCode(gateways);
        result = 31 * result + java.util.Objects.hashCode(registry);
        result = 31 * result + java.util.Objects.hashCode(factory);
        result = 31 * result + java.util.Objects.hashCode(router);
        result = 31 * result + java.util.Objects.hashCode(finality);
        result = 31 * result + java.util.Objects.hashCode(txGasCap);
        result = 31 * result + java.util.Objects.hashCode(tokens);
        result = 31 * result + java.util.Objects.hashCode(gas);
        result = 31 * result + java.util.Objects.hashCode(gasOptIn);
        result = 31 * result + java.util.Objects.hashCode(maxValidSecs);
        result = 31 * result + java.util.Objects.hashCode(verifiers);
        result = 31 * result + java.util.Objects.hashCode(verifierPolicy);
        result = 31 * result + java.util.Objects.hashCode(dexes);
        result = 31 * result + java.util.Objects.hashCode(wrappers);
        result = 31 * result + java.util.Objects.hashCode(familyParams);
        result = 31 * result + java.util.Objects.hashCode(l1Fee);
        result = 31 * result + java.util.Objects.hashCode(disabledKinds);
        result = 31 * result + java.lang.Boolean.hashCode(pinnedReads);
        return result;
    }

    
    
    

}



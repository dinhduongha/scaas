package uniffi.scaas_sdk;

/**
 * A signed operation handed off (spec §27.5 (c)): the operation's named fields as signed (canonical), its signature in the
 * entry's form, the signer's subject id and kind. It holds no secret; who holds it can land it, never redirect it.
 */
public class SignedOpBlob {
    /**
     * 1
     */
    private int v;
    /**
     * the profile's `chain_uid` (`0x` + 64 hex)
     */
    private java.lang.String chainUid;
    /**
     * `evm`, `soroban`
     */
    private java.lang.String family;
    /**
     * the domain's contract, the token (`0x` + 40 hex; a `C…` on Soroban)
     */
    private java.lang.String contract;
    /**
     * the contract function (`mtxPay`, `mtxCancelNonce`, …; `pay`, `transfer`, `burn` on Soroban)
     */
    private java.lang.String entry;
    /**
     * the signed struct
     */
    private java.lang.String name;
    /**
     * the domain kind (`token`)
     */
    private java.lang.String kind;
    /**
     * the struct's fields, canonical (an unbound `relayer` and `feeRecipient` 0)
     */
    private Value message;
    /**
     * what the entry takes unsigned beside them (a pay's `meta`, …)
     */
    private Value extra;
    /**
     * the signature in the entry's form (`bytes`, a `UASig`)
     */
    private Value signature;
    /**
     * the signer's subject id (the lane's `from`)
     */
    private java.lang.String signer;
    /**
     * the signer's kind (a UA kind, 0 a native EVM key)
     */
    private short signerKind;
    /**
     * the transfer on ids (`mtxExecuteTransfer`)
     */
    private boolean ids;

    public SignedOpBlob(
        int v, 
        java.lang.String chainUid, 
        java.lang.String family, 
        java.lang.String contract, 
        java.lang.String entry, 
        java.lang.String name, 
        java.lang.String kind, 
        Value message, 
        Value extra, 
        Value signature, 
        java.lang.String signer, 
        short signerKind, 
        boolean ids
    ) {
        
        this.v = v;
        
        this.chainUid = chainUid;
        
        this.family = family;
        
        this.contract = contract;
        
        this.entry = entry;
        
        this.name = name;
        
        this.kind = kind;
        
        this.message = message;
        
        this.extra = extra;
        
        this.signature = signature;
        
        this.signer = signer;
        
        this.signerKind = signerKind;
        
        this.ids = ids;
    }
    
    public int v() {
        return this.v;
    }
    
    public java.lang.String chainUid() {
        return this.chainUid;
    }
    
    public java.lang.String family() {
        return this.family;
    }
    
    public java.lang.String contract() {
        return this.contract;
    }
    
    public java.lang.String entry() {
        return this.entry;
    }
    
    public java.lang.String name() {
        return this.name;
    }
    
    public java.lang.String kind() {
        return this.kind;
    }
    
    public Value message() {
        return this.message;
    }
    
    public Value extra() {
        return this.extra;
    }
    
    public Value signature() {
        return this.signature;
    }
    
    public java.lang.String signer() {
        return this.signer;
    }
    
    public short signerKind() {
        return this.signerKind;
    }
    
    public boolean ids() {
        return this.ids;
    }
    public void setV(int v) {
        this.v = v;
    }
    public void setChainUid(java.lang.String chainUid) {
        this.chainUid = chainUid;
    }
    public void setFamily(java.lang.String family) {
        this.family = family;
    }
    public void setContract(java.lang.String contract) {
        this.contract = contract;
    }
    public void setEntry(java.lang.String entry) {
        this.entry = entry;
    }
    public void setName(java.lang.String name) {
        this.name = name;
    }
    public void setKind(java.lang.String kind) {
        this.kind = kind;
    }
    public void setMessage(Value message) {
        this.message = message;
    }
    public void setExtra(Value extra) {
        this.extra = extra;
    }
    public void setSignature(Value signature) {
        this.signature = signature;
    }
    public void setSigner(java.lang.String signer) {
        this.signer = signer;
    }
    public void setSignerKind(short signerKind) {
        this.signerKind = signerKind;
    }
    public void setIds(boolean ids) {
        this.ids = ids;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof SignedOpBlob) {
            SignedOpBlob t = (SignedOpBlob) other;
            return (
              v == t.v && 
              
              java.util.Objects.equals(chainUid, t.chainUid) && 
              
              java.util.Objects.equals(family, t.family) && 
              
              java.util.Objects.equals(contract, t.contract) && 
              
              java.util.Objects.equals(entry, t.entry) && 
              
              java.util.Objects.equals(name, t.name) && 
              
              java.util.Objects.equals(kind, t.kind) && 
              
              java.util.Objects.equals(message, t.message) && 
              
              java.util.Objects.equals(extra, t.extra) && 
              
              java.util.Objects.equals(signature, t.signature) && 
              
              java.util.Objects.equals(signer, t.signer) && 
              
              signerKind == t.signerKind && 
              
              ids == t.ids
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.lang.Integer.hashCode(v);
        result = 31 * result + java.util.Objects.hashCode(chainUid);
        result = 31 * result + java.util.Objects.hashCode(family);
        result = 31 * result + java.util.Objects.hashCode(contract);
        result = 31 * result + java.util.Objects.hashCode(entry);
        result = 31 * result + java.util.Objects.hashCode(name);
        result = 31 * result + java.util.Objects.hashCode(kind);
        result = 31 * result + java.util.Objects.hashCode(message);
        result = 31 * result + java.util.Objects.hashCode(extra);
        result = 31 * result + java.util.Objects.hashCode(signature);
        result = 31 * result + java.util.Objects.hashCode(signer);
        result = 31 * result + java.lang.Short.hashCode(signerKind);
        result = 31 * result + java.lang.Boolean.hashCode(ids);
        return result;
    }

    
    
    

}



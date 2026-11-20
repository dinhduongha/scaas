package uniffi.scaas_sdk;

/**
 * A verdict request (spec §9.3): the verifier's named fields of the operation (`op`: `{entry, args, binding?, amount?,
 * recipient?, unwrap?}`, the proof-carrying entry and its argument struct, as `POST /v1/pqz-verdict` takes them), the
 * statement the token rebuilds and the proof, `0x` hex.
 */
public class PqzVerdictRequest {
    private java.lang.String chain;
    private java.lang.String token;
    private Value op;
    private java.lang.String statement;
    private java.lang.String proof;

    public PqzVerdictRequest(
        java.lang.String chain, 
        java.lang.String token, 
        Value op, 
        java.lang.String statement, 
        java.lang.String proof
    ) {
        
        this.chain = chain;
        
        this.token = token;
        
        this.op = op;
        
        this.statement = statement;
        
        this.proof = proof;
    }
    
    public java.lang.String chain() {
        return this.chain;
    }
    
    public java.lang.String token() {
        return this.token;
    }
    
    public Value op() {
        return this.op;
    }
    
    public java.lang.String statement() {
        return this.statement;
    }
    
    public java.lang.String proof() {
        return this.proof;
    }
    public void setChain(java.lang.String chain) {
        this.chain = chain;
    }
    public void setToken(java.lang.String token) {
        this.token = token;
    }
    public void setOp(Value op) {
        this.op = op;
    }
    public void setStatement(java.lang.String statement) {
        this.statement = statement;
    }
    public void setProof(java.lang.String proof) {
        this.proof = proof;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof PqzVerdictRequest) {
            PqzVerdictRequest t = (PqzVerdictRequest) other;
            return (
              java.util.Objects.equals(chain, t.chain) && 
              
              java.util.Objects.equals(token, t.token) && 
              
              java.util.Objects.equals(op, t.op) && 
              
              java.util.Objects.equals(statement, t.statement) && 
              
              java.util.Objects.equals(proof, t.proof)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(chain);
        result = 31 * result + java.util.Objects.hashCode(token);
        result = 31 * result + java.util.Objects.hashCode(op);
        result = 31 * result + java.util.Objects.hashCode(statement);
        result = 31 * result + java.util.Objects.hashCode(proof);
        return result;
    }

    
    
    

}



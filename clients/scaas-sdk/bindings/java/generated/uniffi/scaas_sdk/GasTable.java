package uniffi.scaas_sdk;

/**
 * A gas table file (spec §13.3, the gas table format): `{format: "scaas.gas-table", v: 2, name, family, assumptions, base,
 * verify}`, each base row `{entry, kind, fresh, gas, measured, source, calldata_gas?, per_byte?: {input, gas, source},
 * save?: {gas, measured, source}, fee_extra?: {gas, measured, source}, ua_extra?: {gas, measured, source}, item?,
 * per_item?: {gas, base_count, source, regular?}, stand_in?, regular?: {gas, measured, source}}`, each verify row
 * `{signer, gas, measured, source, sig_bytes, margin?, item?, per_item?, stand_in?}`, read by [`GasTable::parse`]. One format for the chain's measured rows, a module's table
 * and the SDK's reference table.
 */
public class GasTable {
    /**
     * a module's name, `reference`, or the chain key of a chain's measured rows
     */
    private java.lang.String name;
    /**
     * `evm` (the only family with a table today)
     */
    private java.lang.String family;
    private GasRows rows;

    public GasTable(
        java.lang.String name, 
        java.lang.String family, 
        GasRows rows
    ) {
        
        this.name = name;
        
        this.family = family;
        
        this.rows = rows;
    }
    
    public java.lang.String name() {
        return this.name;
    }
    
    public java.lang.String family() {
        return this.family;
    }
    
    public GasRows rows() {
        return this.rows;
    }
    public void setName(java.lang.String name) {
        this.name = name;
    }
    public void setFamily(java.lang.String family) {
        this.family = family;
    }
    public void setRows(GasRows rows) {
        this.rows = rows;
    }

    

    
    @Override
    public boolean equals(java.lang.Object other) {
        if (other instanceof GasTable) {
            GasTable t = (GasTable) other;
            return (
              java.util.Objects.equals(name, t.name) && 
              
              java.util.Objects.equals(family, t.family) && 
              
              java.util.Objects.equals(rows, t.rows)
              
            );
        };
        return false;
    }
    @Override
    public int hashCode() {
        int result = 17;
        result = 31 * result + java.util.Objects.hashCode(name);
        result = 31 * result + java.util.Objects.hashCode(family);
        result = 31 * result + java.util.Objects.hashCode(rows);
        return result;
    }

    
    
    

}



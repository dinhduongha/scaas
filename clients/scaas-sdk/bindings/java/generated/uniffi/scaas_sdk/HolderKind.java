package uniffi.scaas_sdk;


/**
 * The holder's kind as the app read it from the registry (`singleKey` is per holder: spec set-auditor §4).
 */

public enum HolderKind {
    /**
     * a single key (one signer)
     */
  SINGLE_KEY,
    /**
     * a threshold (`msig`) UA
     */
  THRESHOLD,
    /**
     * a native id with code
     */
  CONTRACT;

  
  
  

}



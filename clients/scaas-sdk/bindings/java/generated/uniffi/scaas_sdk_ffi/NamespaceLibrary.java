package uniffi.scaas_sdk_ffi;


final class NamespaceLibrary {
    static synchronized String findLibraryName(String componentName) {
        String libOverride = System.getProperty("uniffi.component." + componentName + ".libraryOverride");
        if (libOverride != null) {
            return libOverride;
        }
        return "scaas_sdk_ffi";
    }

    static java.lang.foreign.SymbolLookup loadLibrary() {
        String name = findLibraryName("scaas_sdk_ffi");
        if (name.startsWith("/") // Unix absolute path
                || name.startsWith("\\\\") // Windows UNC path
                || (name.length() > 2 && name.charAt(1) == ':')) // Windows drive path (e.g. C:\)
        {
            System.load(name);
        } else {
            System.loadLibrary(name);
        }
        return java.lang.foreign.SymbolLookup.loaderLookup();
    }

    static void uniffiCheckContractApiVersion() {
        int bindingsContractVersion = 30;
        int scaffoldingContractVersion = UniffiLib.ffi_scaas_sdk_ffi_uniffi_contract_version();
        if (bindingsContractVersion != scaffoldingContractVersion) {
            throw new RuntimeException("UniFFI contract version mismatch: try cleaning and rebuilding your project");
        }
    }
    static void uniffiCheckApiChecksums() {
        if (UniffiLib.uniffi_scaas_sdk_ffi_checksum_func_panic_in_call() != ((short) 47992)) {
            throw new RuntimeException("UniFFI API checksum mismatch: try cleaning and rebuilding your project");
        }
    }
}

// Define FFI callback types

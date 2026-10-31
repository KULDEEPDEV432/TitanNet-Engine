// ============================================================================
// TitanNet v10.0 - Official Binary Integrity & SHA-256 Verification Utility
// Copyright (c) 2026 Kuldeep Prajapati (TitanNet Systems Architecture)
// ============================================================================

#include <iostream>
#include <string>
#include <cstdlib>
#include "../include/TitanNet_SDK.h"

int main() {
    std::cout << "========================================================\n";
    std::cout << "  TitanNet Autonomous AI Engine - Integrity Verifier    \n";
    std::cout << "  Publisher : " << TitanNet::SDK::PUBLISHER_NAME << "\n";
    std::cout << "  Version   : " << TitanNet::SDK::ENGINE_VERSION << "\n";
    std::cout << "========================================================\n\n";

    std::cout << "[*] Expected Official SHA-256 Fingerprint:\n    "
              << TitanNet::SDK::CORE_SHA256_HASH << "\n\n";

    std::cout << "[*] Running Windows CertUtil SHA-256 Audit on TitanNet.exe...\n";
    int status = std::system("certutil -hashfile TitanNet.exe SHA256");

    if (status == 0) {
        std::cout << "\n[+] Compare the generated hash above with the official fingerprint.\n";
    } else {
        std::cout << "\n[!] Place TitanNet.exe in the same directory to verify its hash.\n";
    }
    return 0;
}

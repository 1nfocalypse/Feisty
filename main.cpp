#include <iostream>
#include <stdexcept>
#include <bitset>
#include <algorithm>
#include <cstdint>
#include <random>
#include <fstream>
#include <queue>

/*
 *     ______     _      __
 *    / ____/__  (_)____/ /___  __
 *   / /_  / _ \/ / ___/ __/ / / /
 *  / __/ /  __/ (__  ) /_/ /_/ /
 * /_/    \___/_/____/\__/\__, /
 *                       /____/
 ***********************************************************************************************************************
 * Feisty is a means of encrypting data via a viginere cipher. While it is currently equipped to encode data passed as a
 * text file, it can be modified to accept raw binaries. It is licensed under GPLv3. For more information on the
 * license, please see the included license in the directory. For more information on the cryptographic scheme, please
 * check out the writeup I wrote on mathematical cryptography:
 * https://github.com/1nfocalypse/CryptoWriteup?tab=readme-ov-file#feistel-networks
 * For more information on usage, please check out the included README.
 * Have fun!
 * Project music recommendation: RZVX ft. VALAK - YOU BETTER RUN (Techno) - https://www.youtube.com/watch?v=xtJE3_GMZrI
 ***********************************************************************************************************************
 */

// forward declarations
uint32_t customHash(uint32_t num);
std::string iterativeHash(std::string key);
void crypt(bool encOrDec); // 0 = enc | 1 = dec
char Feistel(char x, std::string k, int rounds, bool encOrDec, int iteration); // needs to have iteration number passed too
std::string strXOR(std::string x, std::string y) noexcept;

// main()
// PRE: N/A
// POST: Complete desired execution
// WARNINGS: Not exception safe. Exceptions routed if file not found.
// STATUS: Completed, tested.
int main() {
    while (1) {
        std::string menChoiceProxy;
        std::cout << "    ______     _      __       " << std::endl;
        std::cout << "   / ____/__  (_)____/ /___  __" << std::endl;
        std::cout << "  / /_  / _ \\/ / ___/ __/ / / /" << std::endl;
        std::cout << " / __/ /  __/ (__  ) /_/ /_/ / " << std::endl;
        std::cout << "/_/    \\___/_/____/\\__/\\__, /  " << std::endl;
        std::cout << "                      /____/   " << std::endl;
        std::cout << "---------------------------------------------------\n";
        std::cout << "Warning: Feistel Networks are out of date. For more information, consult the README.\n";
        std::cout << "Created by 1nfocalypse: https://github.com/1nfocalypse\n\n\n";
        std::cout << "Please choose a menu option below.\n";
        std::cout << "---------------------------------------------\n";
        std::cout << "1: Encrypt a file using a Feistel Network\n";
        std::cout << "2. Decrypt a file using a Feistel Network\n";
        std::cout << "3. Quit\n";
        std::cout << "---------------------------------------------\n";
        std::getline(std::cin, menChoiceProxy);
        int menChoice = menChoiceProxy[0] - '0';
        while (menChoice < 1 || menChoice > 3) {
            std::cout << "Invalid choice. Please choose a menu option below.\n";
            std::cout << "---------------------------------------------\n";
            std::cout << "1: Encrypt a file using a Feistel Network\n";
            std::cout << "2. Decrypt a file using a Feistel Network\n";
            std::cout << "3. Quit\n";
            std::cout << "---------------------------------------------\n";
            std::getline(std::cin, menChoiceProxy);
            menChoice = menChoiceProxy[0] - '0';
        }
        switch (menChoice) {
            case 1:
                crypt(0);
                break;
            case 2:
                crypt(1);
                break;
            case 3:
                std::cout << "Quitting...\n";
                return 0;
            default:
                std::cout << "Invalid input detected past catch. Halting...\n";
                return 0;
        }
    }
}

// crypt(bool encOrDec)
// PRE: User choose to enc/dec data.
// POST: Data enc/dec.
// WARNINGS: Not exception safe if file not found.
// STATUS: Completed, tested.
void crypt(bool encOrDec) {
    std::string path;
    std::string key;
    std::string line;
    std::string outfilename;
    if (encOrDec) {
        std::cout << "Please enter the path to the file you are trying to decrypt (include extension):\n";
        std::cout << "--------------------------------------------------------------------------------\n";
    } else {
        std::cout << "Please enter the path to the file you are trying to encrypt (include extension):\n";
        std::cout << "--------------------------------------------------------------------------------\n";
    }
    std::cin >> path;
    bool exists = path.find(".fn") != std::string::npos;
    if (!exists && encOrDec == 1) {
        throw std::invalid_argument("Valid file for decryption not found.\n");
    }
    std::cout << "Please enter the name of the output file (include extension if decrypting):\n";
    std::cout << "---------------------------------------------------------------------------\n";
    std::cin >> outfilename;
    if (!encOrDec) {
        outfilename = outfilename + ".fn";
    }
    std::cout << "Please enter a key to use (improper key will render contents unusable!):\n";
    std::cout << "Minimum key length of 8. Maximum length of 16.\n";
    std::cout << "------------------------------------------------------------------------\n";
    std::cin >> key;
    while (key.length() < 8 || key.length() > 16) {
        std::cout << "Key did not meet length requirements. Please enter 8-16 characters.\n";
        std::cout << "------------------------------------------------------------------------\n";
        std::cin >> key;
    }
    key = iterativeHash(key);
    // key populated with 512 bits. 256 effectively utilized due to key splicing methodology.
    // this is fine: you need to pass context in to know where to start in the key.
	size_t rounds = 16; // consider buffing to 32
	std::ifstream rawFile;
	std::queue<char> eQueue;
	rawFile.open(path.c_str());
	if (rawFile.good()) {
        auto out = std::string();
        auto buf = std::string(100, '\0');
        while (rawFile.read(& buf[0], 100)) {
            out.append(buf, 0, rawFile.gcount());
        }
        out.append(buf, 0, rawFile.gcount());
        line = out;
	} else {
		throw std::invalid_argument("Valid file not found.\n");
	}
	rawFile.close();
	for (size_t i = 0; i < line.length(); i++) {
        // we need to ship the entire key, along with the starting index.
        // for encryption, works normally
        // for decryption, add 16 (# rounds), work backwards.
        // i % key.length()
		eQueue.push(Feistel(line[i],key, rounds, encOrDec, i));
	}
	std::ofstream outfile;
	outfile.open(outfilename);
	while (!eQueue.empty()) {
		outfile << eQueue.front();
		eQueue.pop();
	}
	outfile.close();
    std::cin.ignore();
}

// customHash(int32_t num)
// PRE: key passed as a string
// POST: key padded to 256 bits with deterministic pseudorandomness
// WARNINGS: collisions may occur - collision resistance not tested
// STATUS: Completed, tested.
// Attribution: sourced from https://www.cs.ubc.ca/~rbridson/docs/schechter-sca08-turbulence.pdf
uint32_t customHash(uint32_t num) {
    num = num ^ 2747636419;
    num = (num * 2654435769) % UINT32_MAX;
    num = num ^ (num >> 16);
    num = (num * 2654435769) % UINT32_MAX;
    num = num ^ (num >> 16);
    num = (num * 2654435769) % UINT32_MAX;
    return num;
}

// iterativeHash(std::string key)
// PRE: key passed as a string
// POST: key padded to 256 bits with deterministic pseudorandomness
// WARNINGS: collisions may occur - collision resistance not tested
// STATUS: Completed, tested.
std::string iterativeHash(std::string key) {
    if (key.length() == 64) {
        return key;
    }
    uint32_t baseNum(0);
    // this should fix the ordering issue
    for (size_t i = 0; i < key.length(); ++i) {
        baseNum += static_cast<uint32_t>(key[i]) * i;
    }
    // hash basenum
    uint32_t base = customHash(baseNum);
    std::mt19937 gen(base); // seed the generator
    std::uniform_int_distribution<> distr(32, 255);
    char randomAppend = static_cast<char>(distr(gen));
    key += randomAppend;
    return iterativeHash(key);
}

// Feistel(char x, char k, int rounds, bool encOrDec)
// PRE: x, k, rounds, encOrDec passed
// POST: character has been encrypted/decrypted
// WARNINGS: Strongly exception safe
// STATUS: Completed, tested.
char Feistel(char x, const std::string k, int rounds, bool encOrDec, int iter) {
    std::string clear = std::bitset<8>(x).to_string();
    std::string preR, preL;
    if (encOrDec) {
        preR = clear.substr(0, 4);
        preL = clear.substr(4, 4);
    } else {
        preL = clear.substr(0, 4);
        preR = clear.substr(4, 4);
    }
    std::string newL, newR;
    std::string key;
    for (int i = 0; i < rounds; ++i) {
        int keyIndex = iter + (encOrDec ? i : rounds - i - 1);
        key = std::bitset<8>(k[keyIndex % k.length()]).to_string().substr(0, 4);
        if (encOrDec) {
            newR = strXOR(preL, strXOR(preR, key));
            newL = preR;
        } else {
            newL = strXOR(preR, strXOR(preL, key));
            newR = preL;
        }
        preL = newL;
        preR = newR;
    }
    std::string str;
    if (encOrDec) {
        str = preL + preR;
    } else {
        str = preR + preL;
    }
    int num = std::stoi(str, 0, 2);
    char retChar = static_cast<char>(num);
    return retChar;
}

// strXOR(std::string r, std::string k)
// PRE: r, k are 4 char strings representing binary numbers
// POST: result of r XOR k is returned.
// WARNING: Noexcept
// STATUS: Completed, tested
std::string strXOR(std::string r, std::string k) noexcept {
    std::string retStr = "";
    for (size_t i = 0; i < 4; i++) {
        if (r[i] == '1' || k[i] == '1') {
            if (r[i] == '1' && k[i] == '1') {
                retStr.append("0");
            } else {
                retStr.append("1");
            }
        } else {
            retStr.append("0");
        }
    }
    return retStr;
}
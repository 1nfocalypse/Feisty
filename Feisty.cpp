#include <iostream>
#include <fstream>
#include <stdexcept>
#include <queue>
#include <bitset>
#include <string>
#include <algorithm>

void crypt(bool encOrDec); // 0 = enc | 1 = dec
char Feistel(char x, char k, int rounds, bool encOrDec);
std::string strXOR(std::string x, std::string y);

// pre: N/A
// post: Interactable Menu Printed
// warnings: N/A
int main() {
	size_t menChoice;
	while (1) {
		std::cout << "    ______     _      __       " << std::endl;
		std::cout << "   / ____/__  (_)____/ /___  __" << std::endl;
		std::cout << "  / /_  / _ \\/ / ___/ __/ / / /" << std::endl;
		std::cout << " / __/ /  __/ (__  ) /_/ /_/ / " << std::endl;
		std::cout << "/_/    \\___/_/____/\\__/\\__, /  " << std::endl;
		std::cout << "                      /____/   " << std::endl;
		std::cout << "---------------------------------------------------\n";
		std::cout << "Warning: Feistel Networks are out of date. Please DO NOT use for legitimate encryption.\n";
		std::cout << "By using this program, you acknowledge you are solely responsible for any damages.\n";
		std::cout << "Created by 1nfocalypse: https://github.com/1nfocalypse\n\n\n";
		std::cout << "Please choose a menu option below.\n";
		std::cout << "---------------------------------------------\n";
		std::cout << "1: Encrypt a file using a Feistel Network\n";
		std::cout << "2. Decrypt a file using a Feistel Network\n";
		std::cout << "3. Quit\n";
		std::cout << "---------------------------------------------\n";
		std::cin >> menChoice;
		while (menChoice < 1  || menChoice > 3) {
			std::cout << "Please pick a valid menu option.\n";
			std::cin >> menChoice;
		}
		if (menChoice == 1) {
			crypt(0);
		} else if (menChoice == 2) {
			crypt(1);
		} else {
			return 0;
		}
	}
	return 0;
}

// pre: A user uses the menu, passes encOrDec : 1 = dec, 0 = enc
// post: The file is encrypted or decrypted
// warnings: If a file is not found, a bad argument exception will be thrown.
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
	std::cout << "------------------------------------------------------------------------\n";
	std::cin >> key;
	size_t rounds = key.length();
	std::ifstream rawFile;
	std::queue<char> eQueue;
	rawFile.open(path.c_str());
	if (encOrDec) {
		std::reverse(key.begin(), key.end());
	}
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
		eQueue.push(Feistel(line[i],key[i % key.length()], rounds, encOrDec));
	}
	std::ofstream outfile;
	outfile.open(outfilename);
	while (!eQueue.empty()) {
		outfile << eQueue.front();
		eQueue.pop();
	}
	outfile.close();
}

// pre: x, k, rounds, encOrDec passed
// post: character has been decrypted
// warnings: N/A
char Feistel(char x, char k, int rounds, bool encOrDec) {
	std::string clear = std::bitset<8>(x).to_string();
	std::string key = std::bitset<8>(k).to_string().substr(0,4);
	std::string preR, preL;
	if (encOrDec) {
		preR = clear.substr(0,4);
		preL = clear.substr(4,8);
	} else {
		preL = clear.substr(0,4);
		preR = clear.substr(4,8);
	}
	std::string newL, newR;
	for (int i = 0; i < rounds; i++) {
		if (!encOrDec) {
			newL = preR;
			newR = strXOR(preL, strXOR(preR, key));
			preL = newL;
			preR = newR;
		} else {
			newR = preL;
        	newL = strXOR(preR, strXOR(preL, key));
        	preL = newL;
        	preR = newR;
		}
	}
	std::string str;
	if (encOrDec) {
		str = preL + preR;
	} else {
		str = preR + preL;
	}
	int num = std::stoi(str,0,2);
	char retChar = (char)num;
	return retChar;
}

// pre: r, k are strings representing binary numbers
// post: result of r XOR k is returned.
// error: N/A
std::string strXOR(std::string r, std::string k) {
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

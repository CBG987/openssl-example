#include "crypto.hpp"
#include "passwordcrack.cpp"
#include <iostream>

using namespace std;

int main() {
  cout << "SHA-1 with 1 iteration" << endl;
  cout << Crypto::hex(Crypto::sha1("Test")) << endl << endl;
  
  cout << "SHA-1 with two iterations" << endl;
  cout << Crypto::hex(Crypto::sha1(Crypto::sha1("Test"))) << endl << endl;

  cout << "The derived key from the PBKDF2 algorithm" << endl;
  cout << Crypto::hex(Crypto::pbkdf2("Password", "Salt")) << endl << endl;
  
  cout << "MD5" << endl;
  cout << Crypto::hex(Crypto::md5("Test")) << endl << endl;
  
  cout << "SHA256" << endl;
  cout << Crypto::hex(Crypto::sha256("Test")) << endl << endl;
  
  cout << "SHA512" << endl;
  cout << Crypto::hex(Crypto::sha512("Test")) << endl << endl;
  
  cout << "Crack of Olas password" << endl;
  cout << Crack() << endl;
}

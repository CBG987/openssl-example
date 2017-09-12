#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <string>

using namespace std;

static std::string hex(const std::string &input) {
  std::stringstream hex_stream;
  hex_stream << std::hex << std::internal << std::setfill('0');
  for (auto &byte : input)
    hex_stream << std::setw(2) << (int)(unsigned char)byte;
  return hex_stream.str();
}

static std::string pbkdf2(const std::string &password, const std::string &salt, int iterations = 4096, int key_length = 256 / 8) {
  std::string key;
  key.resize(key_length);
  auto success = PKCS5_PBKDF2_HMAC_SHA1(password.data(), password.size(),
                                        (const unsigned char *)salt.data(), salt.size(), iterations,
                                        key_length, (unsigned char *)key.data());
  if (!success)
    throw std::runtime_error("openssl: error calling PBKCS5_PBKDF2_HMAC_SHA1");
  return key;
}

string Crack() {
  string hash = "ab29d7b5c589e18b52261ecba1d3a7e7cbf212c6";
  string salt = "Saltet til Ola";
  int iterasjoner = 2048;
  string passord;
  passord.resize(3);
  
  for(int i=65; i<=122; i++){
    for(int j=65; j<=122; j++){
      for(int k=65; k<=122; k++){
        passord[0] = char(i);
        passord[1] = char(j);
        passord[2] = char(k);
        
        if(hex(pbkdf2(passord, salt, iterasjoner, 20)) == hash){
          return passord;
        }
      }
    }
  }
  
  return "";
}

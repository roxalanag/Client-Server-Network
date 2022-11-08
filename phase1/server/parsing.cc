#include <cassert>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "../common/contextmanager.h"
#include "../common/crypto.h"
#include "../common/err.h"
#include "../common/net.h"
#include "../common/protocol.h"

#include "parsing.h"
#include "responses.h"

using namespace std;


/// Helper method to check if provided block of data is kblock
/// @param block The block of data
///
/// @returns True if is kblock. False otherwise
bool is_kblock(vec &block){
  string cmd = (char*) block.data();
    if (cmd == REQ_KEY)
      return true;
    return false;
}

/// When a new client connection is accepted, this code will run to figure out
/// what the client is requesting, and to dispatch to the right function for
/// satisfying the request.
///
/// @param sd      The socket on which communication with the client takes place
/// @param pri     The private key used by the server
/// @param pub     The public key file contents, to possibly send to the client
/// @param storage The Storage object with which clients interact
///
/// @return true if the server should halt immediately, false otherwise
bool parse_request(int sd, RSA *pri, const vector<uint8_t> &pub,
                   Storage *storage) {
  //getting encrypted rblock 
  vec encRBlock; 
  encRBlock.reserve(LEN_RKBLOCK);
  reliable_get_to_eof_or_n(sd, encRBlock.begin(), 256);
  encRBlock.resize(LEN_RKBLOCK);

  //rsa decryption on rblock
  vec decRBlock;
  decRBlock.reserve(LEN_RKBLOCK);

  unsigned char temp[LEN_RKBLOCK];
  RSA_private_decrypt(encRBlock.size(), encRBlock.data(), temp, pri, RSA_PKCS1_OAEP_PADDING);
  for (int k = 0; k < LEN_RKBLOCK; k++){
    decRBlock.push_back(temp[k]);
  }
  decRBlock.resize(LEN_RKBLOCK);
  vec clientCMD;

  for (int k = 0; k < 3; k++){
    clientCMD.push_back(decRBlock.at(k));
  }
  string cmd = (char*) clientCMD.data();
  vec aeskey;

  for (int k = 3; k < 51; k++){
    aeskey.push_back(decRBlock.at(k));
  }

  int encABlockSIZE = decRBlock.at(52);

  //getting encrypted ablock
  int reads = encABlockSIZE / LEN_RKBLOCK;
  int lastRead = encABlockSIZE % LEN_RKBLOCK;
  int index = LEN_RKBLOCK;
  vec encABlock;
  encABlock.reserve(LEN_CONTENT + LEN_PASS + LEN_UNAME + 4);
  for (int k = 0; k < reads; k++ ){
    reliable_get_to_eof_or_n(sd, encABlock.begin() + index, 256);
    index += LEN_RKBLOCK;
  }
  reliable_get_to_eof_or_n(sd, encABlock.begin() + index, lastRead);

  // decrypting a block
  EVP_CIPHER_CTX *aes_ctx = create_aes_context(aeskey, false);
  vec decABlock = aes_crypt_msg(aes_ctx, encABlock);
  aes_ctx = create_aes_context(aeskey, true);


  // Iterates through possible commands, picks the right one, and runs it
  if(!is_kblock(clientCMD)){
    vector<string> s = {REQ_REG, REQ_BYE, REQ_SAV, REQ_SET, REQ_GET, REQ_ALL};
    decltype(handle_reg) *cmds[] = {handle_reg, handle_bye, 
                                    handle_sav, handle_set, handle_get, handle_all};
      for (size_t i = 0; i < s.size(); ++i) {
        if (cmd == s[i]) {
          return cmds[i](sd, storage, aes_ctx, encABlock);
        }
      }
    }
    else{
      server_cmd_key(sd, pub);
  }
  return false;
}

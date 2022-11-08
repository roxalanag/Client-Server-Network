#include <cassert>
#include <cstring>
#include <iostream>
#include <openssl/rand.h>
#include <vector>

#include "../common/contextmanager.h"
#include "../common/crypto.h"
#include "../common/file.h"
#include "../common/net.h"
#include "../common/protocol.h"

#include "requests.h"

using namespace std;

/// auth_msg() is a helper function for configuring the aBlock
///
/// @param user The name of the user going into the aBlock
/// @param pass The password of the user going into the aBlock
vec auth_msg(const string &user, const string &pass) {

  vec aBlock;
    int userlen = (int) user.length();
    int passlen = (int) pass.length();

    aBlock.insert(aBlock.end(), (char*) &userlen, ((cher*) &userlen) + sizeof(int));
    aBlock.insert(aBlock.end(), user.begin(), user.end());
    aBlock.inser(aBlock.end(), (char *) &passlen, ((char *) &passlen) + sizeof(int));
    aBlock.insert(aBlock.end(), pass.begin(), pass.end());
    return aBlock;
}

/// client_send_cmd() sends an encrypted message to the server
///
/// @param sd     The socket descriptor for communicating with the server
/// @param pub    The public key of the server
/// @param cmd    The command being sent to the server
/// @param aBlock The authentication block of the user
vec client_send_cmd(int sd, RSA *pub, const string &cmd, const vec &aBlock) {
  //ENCRYPT THE A BLOCK 
    vec aeskey = create_aes_key();
    EVP_CIPHER_CTX *ctx = create_aes_context(aeskey, true);
    vec encABlock = aes_crypt_msg(ctx, aBlock);
    
  //MAKE R BLOCK
    vec rBlock;    

    rBlock.push_back(cmd.at(0));
    rBlock.push_back(cmd.at(1));
    rBlock.push_back(cmd.at(2));
    rBlock.insert(rBlock.end(), aeskey.begin(), aeskey.end());      
    rBlock.push_back(encABlock.size());
    
    //ENCRYPT R BLOCK
    vec encRBlock;
    encRBlock.reserve(LEN_RKBLOCK);
    unsigned char temp[LEN_RKBLOCK];
    RSA_public_encrypt(rBlock.size(), rBlock.data(), temp, pub, RSA_PKCS1_OAEP_PADDING);
    for (int k = 0; k < LEN_RKBLOCK; k++){
      encRBlock.push_back(temp[k]);
    }
    encRBlock.resize(LEN_RKBLOCK);
    
    //Append ablock contents to rblock
    encRBlock.insert(encRBlock.end(), encABlock.begin(), encABlock.end());

    // SEND STUFF BLOCK 
    if (!(send_reliably(sd, encRBlock)))
      cerr << "Client: Error sending rBlock";
  
   //RECIEVE SERVER OUTPUT
    vec encServerResponse = reliable_get_to_eof(sd);
     
    //DECRYPT SERVER OUTPUT
    if (!(reset_aes_context(ctx, aeskey, false))) 
          cerr << "Client: Error resetting aes context";
    vec decServerResponse = aes_crypt_msg(ctx, encServerResponse);

    //PRINT SERVER OUTPUT GET THAT GREEN OKAY BABYE
    return decServerResponse;

}



/// req_key() writes a request for the server's key on a socket descriptor.
/// When it gets a key back, it writes it to a file.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param keyfile The name of the file to which the key should be written
void req_key(int sd, const string &keyfile) {
  cout << "requests.cc::req_key() is not implemented\n";
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(keyfile.length() > 0);
}

/// req_reg() sends the REG command to register a new user
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
void req_reg(int sd, RSA *pubkey, const string &user, const string &pass,
             const string &, const string &) {
  cout << "requests.cc::req_reg() is not implemented\n";
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(pubkey);
  assert(user.length() > 0);
  assert(pass.length() > 0);
}

/// req_bye() writes a request for the server to exit.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
void req_bye(int sd, RSA *pubkey, const string &user, const string &pass,
             const string &, const string &) {
  cout << "requests.cc::req_bye() is not implemented\n";
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(pubkey);
  assert(user.length() > 0);
  assert(pass.length() > 0);
}

/// req_sav() writes a request for the server to save its contents
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
void req_sav(int sd, RSA *pubkey, const string &user, const string &pass,
             const string &, const string &) {
  cout << "requests.cc::req_sav() is not implemented\n";
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(pubkey);
  assert(user.length() > 0);
  assert(pass.length() > 0);
}

/// req_set() sends the SET command to set the content for a user
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
/// @param setfile The file whose contents should be sent
void req_set(int sd, RSA *pubkey, const string &user, const string &pass,
             const string &setfile, const string &) {
  cout << "requests.cc::req_set() is not implemented\n";
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(pubkey);
  assert(user.length() > 0);
  assert(pass.length() > 0);
  assert(setfile.length() > 0);
}

/// req_get() requests the content associated with a user, and saves it to a
/// file called <user>.file.dat.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
/// @param getname The name of the user whose content should be fetched
void req_get(int sd, RSA *pubkey, const string &user, const string &pass,
             const string &getname, const string &) {
  cout << "requests.cc::req_get() is not implemented\n";
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(pubkey);
  assert(user.length() > 0);
  assert(pass.length() > 0);
  assert(getname.length() > 0);
}

/// req_all() sends the ALL command to get a listing of all users, formatted
/// as text with one entry per line.
///
/// @param sd      The open socket descriptor for communicating with the server
/// @param pubkey  The public key of the server
/// @param user    The name of the user doing the request
/// @param pass    The password of the user doing the request
/// @param allfile The file where the result should go
void req_all(int sd, RSA *pubkey, const string &user, const string &pass,
             const string &allfile, const string &) {
  cout << "requests.cc::req_all() is not implemented\n";
  // NB: These asserts are to prevent compiler warnings
  assert(sd);
  assert(pubkey);
  assert(user.length() > 0);
  assert(pass.length() > 0);
  assert(allfile.length() > 0);
}

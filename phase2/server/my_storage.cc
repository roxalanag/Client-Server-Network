#include <cassert>
#include <cstring>
#include <functional>
#include <iostream>
#include <openssl/rand.h>
#include <string>
#include <vector>

#include "../common/contextmanager.h"
#include "../common/err.h"
#include "../common/protocol.h"

#include "authtableentry.h"
#include "format.h"
#include "map.h"
#include "map_factories.h"
#include "storage.h"
#include "../common/file.h"

using namespace std;

/// MyStorage is the student implementation of the Storage class
class MyStorage : public Storage {
  /// The map of authentication information, indexed by username
  Map<string, AuthTableEntry> *auth_table;

  /// The map of key/value pairs
  Map<string, vector<uint8_t>> *kv_store;

  /// The name of the file from which the Storage object was loaded, and to
  /// which we persist the Storage object every time it changes
  string filename = "";

public:
  /// Construct an empty object and specify the file from which it should be
  /// loaded.  To avoid exceptions and errors in the constructor, the act of
  /// loading data is separate from construction.
  ///
  /// @param fname   The name of the file to use for persistence
  /// @param buckets The number of buckets in the hash table
  /// @param upq     The upload quota
  /// @param dnq     The download quota
  /// @param rqq     The request quota
  /// @param qd      The quota duration
  /// @param top     The size of the "top keys" cache
  /// @param admin   The administrator's username
  MyStorage(const std::string &fname, size_t buckets, size_t, size_t, size_t,
            double, size_t, const std::string &)
      : auth_table(authtable_factory(buckets)),
        kv_store(kvstore_factory(buckets)), filename(fname) {}

  /// Destructor for the storage object.
  virtual ~MyStorage() {}

  /// Create a new entry in the Auth table.  If the user already exists, return
  /// an error.  Otherwise, create a salt, hash the password, and then save an
  /// entry with the username, salt, hashed password, and a zero-byte content.
  ///
  /// @param user The user name to register
  /// @param pass The password to associate with that user name
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t add_user(const string &user, const string &pass) {
    //authorize the user 
    if (user.length() > LEN_UNAME || pass.length() > LEN_PASSWORD) {
      return {true, RES_ERR_LOGIN, {}}; 
    }
    //create salt 
    unsigned char salt[LEN_SALT];

    //create an entry
    AuthTableEntry entry;
    //initialize username and salt 
    entry.username = user; 
    entry.salt = vector<uint8_t>(salt, salt+LEN_SALT); 

    //make a buffer for storing hash passwords 
    unsigned char hashBuffer[LEN_PASSHASH]; 
    SHA256_CTX ctx; 
    SHA256_Init(&ctx); 
    SHA256_Update(&ctx, pass.data(), pass.length()); 
    SHA256_Final(hashBuffer, &ctx); 
    //create buffer 32 bytes long 
    char buffer[32]; 
    string hashPass; 
    for (int i=0; i<LEN_PASSHASH; i++) {
      sprintf(buffer, "%02x", hashBuffer[i]); 
      hashPass.append(buffer); 
    }

    //assign the hashed password to new entry 
    entry.pass_hash = vector<uint8_t>(hashPass.begin(), hashPass.end()); 
    //emptry the contents of entry
    entry.content = {};

    //check for checking if the user already exists 
    bool check = false;

    if(auth_table->insert(user, entry, [](){})) {
      check = true; 
    } 
    if (check) {
      return {true, RES_OK, {}}; 
    }
    //throw error if the user already exists 
    return {false, RES_ERR_USER_EXISTS, {}}; 
  }

  /// Set the data bytes for a user, but do so if and only if the password
  /// matches
  ///
  /// @param user    The name of the user whose content is being set
  /// @param pass    The password for the user, used to authenticate
  /// @param content The data to set for this user
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t set_user_data(const string &user, const string &pass,
                                 const vector<uint8_t> &content) {
    
    //check user and passw authentication 
    auto authorization = auth(user, pass); 
    if(!authorization.succeeded) {
      return {false, RES_ERR_LOGIN, {}};
    }

    //make a buffer for storing hash passwords 
    unsigned char hashBuffer[LEN_PASSHASH]; 
    SHA256_CTX ctx; 
    SHA256_Init(&ctx); 
    SHA256_Update(&ctx, pass.data(), pass.length()); 
    SHA256_Final(hashBuffer, &ctx); 
    //create buffer 32 bytes long 
    char buffer[32]; 
    string hashPass; 
    for (int i=0; i<LEN_PASSHASH; i++) {
      sprintf(buffer, "%02x", hashBuffer[i]); 
      hashPass.append(buffer); 
    }

    auto setAuth = [&](AuthTableEntry &entry) {
      entry.content = content; 
    }; 
    if(auth_table->do_with(user, setAuth)) {
      return {true, RES_OK, {}};
    }
    

    return {false, RES_ERR_SERVER, {}};
  }

  /// Return a copy of the user data for a user, but do so only if the password
  /// matches
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param who  The name of the user whose content is being fetched
  ///
  /// @return A result tuple, as described in storage.h.  Note that "no data" is
  ///         an error
  virtual result_t get_user_data(const string &user, const string &pass,
                                 const string &who) {

    //authentication 
    auto authentication = auth(user, pass); 
    if (!authentication.succeeded) {
      return {false, RES_ERR_LOGIN, {}}; 
    }

    //declare vector w authorization data 
    vector<uint8_t> authVec; 

    auto authData = [&](const AuthTableEntry &authEntry) {
      authVec = vector<uint8_t>(authEntry.content.begin(), authEntry.content.end()); 
      vector<uint8_t> authContent = authEntry.content; 
      authContent.insert(authContent.end(), authVec.begin(), authVec.end());
    };
    auth_table->do_with_readonly(who, authData); 

    //check if there is data 
    if (authVec.size() !=0) {
      //return okay if there's data 
      return {true, RES_OK, {authVec}};
    }
    else {
      //in case there is no data 
      return {false, RES_ERR_NO_DATA, {authVec}};
    }

    return {false, RES_ERR_SERVER, {}};
  }

  /// Return a newline-delimited string containing all of the usernames in the
  /// auth table
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t get_all_users(const string &user, const string &pass) {

    //authentication 
    auto authentication = auth(user, pass); 
    if (!authentication.succeeded) {
      return {false, RES_ERR_LOGIN, {}}; 
    }

    //vector to hold user values 
    vector<uint8_t> userVec; 

    auto allUsers = [&](const string key, const AuthTableEntry &entry) {
      assert(entry.username.length() > 0); 
      userVec.insert(userVec.end(), key.begin(), key.end()); 
      userVec.insert(userVec.end(), '\n'); 
      vector<uint8_t> username(user.begin(), user.end()); 
      userVec.insert(userVec.end(), username.begin(), username.end()); 
    }; 
    auth_table->do_all_readonly(allUsers, [](){}); 

    return {true, RES_OK, userVec};
  }

  /// Authenticate a user
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t auth(const string &user, const string &pass) {
    //authorize the user 
    if (user.length() > LEN_UNAME || pass.length() > LEN_PASSWORD) {
      return {true, RES_ERR_LOGIN, {}}; //could not authenticate user
    }

    bool check = false; 
    //make a buffer for storing hash passwords 
    unsigned char hashBuffer[LEN_PASSHASH]; 
    SHA256_CTX ctx; 
    SHA256_Init(&ctx); 
    SHA256_Update(&ctx, (const unsigned char*)pass.c_str(), pass.length()); 
    SHA256_Final(hashBuffer, &ctx); 
    //create buffer 32 bytes long 
    char buffer[32]; 
    string hashPass; 
    for (int i=0; i<LEN_PASSHASH; i++) {
      sprintf(buffer, "%02x", hashBuffer[i]); 
      hashPass.append(buffer); 
    }

    auto passwCheck = [&](const AuthTableEntry &entry) {
      string entryHash(entry.pass_hash.begin(), entry.pass_hash.end()); 
      if (entryHash == hashPass) {
        check = true; 
      }
    }; 

    auth_table->do_with_readonly(user, passwCheck); 

    if (!check) {
      return {false, RES_ERR_NO_USER, {}}; 
    }
    return {true, RES_OK, {}}; 

  }

  /// Create a new key/value mapping in the table
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose mapping is being created
  /// @param val  The value to copy into the map
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_insert(const string &user, const string &pass,
                             const string &key, const vector<uint8_t> &val) {

    if (auth(user, pass).succeeded) {
      if (!kv_store->insert(key, val, [](){})) {
        //return ok if no errors 
        return {false, RES_ERR_KEY, {}};
      }
      //insert in the kv pair
      return {true, RES_OK, {}};
    }

    return {false, RES_ERR_LOGIN, {}};
  };

  /// Get a copy of the value to which a key is mapped
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose value is being fetched
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_get(const string &user, const string &pass,
                          const string &key) {

    if (!auth(user, pass).succeeded) {
      return {false, RES_ERR_LOGIN, {}}; //Could not validate credentials
    }

    vector<uint8_t> data; 
    auto get_data = [&](vector<uint8_t> entry) {
      data = entry; 
    };

    if (!kv_store->do_with_readonly(key, get_data)) {
      return {false, RES_ERR_KEY, {}}; 
    }

    if (!data.size()) {
      return {false, RES_ERR_NO_DATA, {}};
    }

    return {true, RES_OK, data};
  };

  /// Delete a key/value mapping
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose value is being deleted
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_delete(const string &user, const string &pass,
                             const string &key) {

    if (auth(user, pass).succeeded) {
      if (!kv_store->remove(key, [](){})) {
        return {false, RES_ERR_KEY, {}}; 
      }
      return {true, RES_OK, {}};
    }
    return {false, RES_ERR_LOGIN, {}}; //if could not validate credentials
  };

  /// Insert or update, so that the given key is mapped to the give value
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose mapping is being upserted
  /// @param val  The value to copy into the map
  ///
  /// @return A result tuple, as described in storage.h.  Note that there are
  ///         two "OK" messages, depending on whether we get an insert or an
  ///         update.
  virtual result_t kv_upsert(const string &user, const string &pass,
                             const string &key, const vector<uint8_t> &val) {

    auto r = auth(user, pass); //All response messages to send back
    if (!r.succeeded)
      return {false, r.msg, {}}; //Could not validate credentials
    if (kv_store->upsert(key, vector(val), [](){}, [](){}))  //after authentication
      return {true, RES_OKINS, {}};
    return {true, RES_OKUPD, {}};
  };

  /// Return all of the keys in the kv_store, as a "\n"-delimited string
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_all(const string &user, const string &pass) {
    if(!auth(user, pass).succeeded) {
      return {false, RES_ERR_LOGIN, {}}; //could not validate credentials
    }
    vector<uint8_t> data; //Now get the keys and append '\n' character onto them
    auto allKeys = [&](const string key, const vector<uint8_t> &val) {
      assert(val.size() > 0); 
      data.insert(data.end(), key.begin(), key.end()); 
      data.insert(data.end(), '\n');
    };
    kv_store->do_all_readonly(allKeys, [](){}); 

    if(data.size() > 0) {
      return {true, RES_OK, {data}}; 
    }
     return {false, RES_ERR_NO_DATA, {}};
  };

  /// Shut down the storage when the server stops.  This method needs to close
  /// any open files related to incremental persistence.  It also needs to clean
  /// up any state related to .so files.  This is only called when all threads
  /// have stopped accessing the Storage object.
  virtual void shutdown() {
    return; 
  }

  /// Write the entire Storage object to the file specified by this.filename. To
  /// ensure durability, Storage must be persisted in two steps.  First, it must
  /// be written to a temporary file (this.filename.tmp).  Then the temporary
  /// file can be renamed to replace the older version of the Storage object.
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t save_file() {
    FILE *file = fopen((filename+".tmp").c_str(), "w"); 
    if (file == nullptr) {
      return {true, "File does not exist: " + filename, {}};
    }
    vector<uint8_t> pair; 
    //KV entry 
    auto KV_entry = [&](const string key, const vector<uint8_t> &val) {
      int v_length = val.size(); 
      int k_length = key.size(); 
      int padding = (8 - (k_length + v_length + KVENTRY.size() + pair.size()) % 8); 
      pair.reserve((k_length + v_length + KVENTRY.size() + pair.size()) + padding); 
      pair.insert(pair.end(), KVENTRY.begin(), KVENTRY.end()); 
      pair.insert(pair.end(), v_length, v_length+sizeof(int)); 
      pair.insert(pair.end(), k_length, k_length+sizeof(int)); 
      pair.insert(pair.end(), key.begin(), key.end()); 
      pair.insert(pair.end(), val.begin(), val.end()); 

      fwrite(pair.data(), sizeof(vector<uint8_t>), pair.size(), file); 
    };

    //authentication entry 
    auto auth_entry = [&]() {
      auth_table->do_all_readonly([](const string user, const AuthTableEntry &entry) {
        vector<uint8_t> vecAuth; 
        vecAuth.insert(vecAuth.end(), AUTHENTRY.begin(), AUTHENTRY.end());

        int u_length = user.length(); 
        int s_length = entry.salt.size(); 
        int hp_length = entry.pass_hash.size(); 
        int padding = (8 - (u_length + s_length + AUTHENTRY.size() + vecAuth.size() + hp_length) % 8);
        vecAuth.reserve((u_length + s_length + AUTHENTRY.size() + vecAuth.size() + hp_length) + padding); 
        vecAuth.insert(vecAuth.end(), u_length, u_length + sizeof(int)); 
        vecAuth.insert(vecAuth.end(), s_length, s_length + sizeof(int)); 
        vecAuth.insert(vecAuth.end(), hp_length, hp_length + sizeof(int)); 
        vecAuth.insert(vecAuth.end(), user.begin(), user.end()); 
        vecAuth.insert(vecAuth.end(), entry.salt.begin(), entry.salt.end()); 
        vecAuth.insert(vecAuth.end(), entry.pass_hash.begin(), entry.pass_hash.end()); 
      }, [](){}); 
    };

    kv_store->do_all_readonly(KV_entry, auth_entry); 

    fclose(file); 
    rename((filename+".tmp").c_str(), filename.c_str()); 
    return {true, RES_OK, {}}; 

  }

  /// Populate the Storage object by loading this.filename.  Note that load()
  /// begins by clearing the maps, so that when the call is complete, exactly
  /// and only the contents of the file are in the Storage object.
  ///
  /// @return A result tuple, as described in storage.h.  Note that a
  ///         non-existent file is not an error.
  virtual result_t load_file() {
    FILE *storage_file = fopen(filename.c_str(), "r");
    if (storage_file == nullptr) {
      return {true, "File not found: " + filename, {}};
    }
    return {true, "File not found: " + filename, {}};
    // if(!file_exists(filename)){
    //   return {true, "File does not exist: " + filename, {}};
    // }
    // vector <uint8_t> file_data = load_entire_file(filename);

    // std::size_t use_size = 0;

    // while(use_size < file_data.size()){
    //   //USE use_size as an indicator of position and use this to load AUTHAUTH and KVKVKVKV and then 
    //   //compare these two values to given strings to move forward
    //   string header;
    //   for(int i = 0; i < 8; i++)
    //   {
    //     header += file_data[use_size + i];
    //   }

    //   if(header.compare("AUTHAUTH") == 0)
    //   {
    //     unsigned int uname_length = 0;
    //     for(int i =0; i <4; i++)
    //     {
    //       uname_length |= ((unsigned int)file_data[8+i+use_size] << 8*i);
    //     }

    //     string uname;
    //     for(int j = 0; j < static_cast<int>(uname_length); j++)
    //     {
    //       uname += file_data[12 +j+use_size];
    //     }
        
    //     unsigned int pass_hash_length =0; 
    //     for(int i =0; i <4; i++)
    //     {
    //       pass_hash_length |= ((unsigned int)file_data[12+i+uname_length+use_size] << 8*i);
    //     }
        
    //     string pass_hash;
    //     for(int j = 0; j < static_cast<int>(pass_hash_length); j++)
    //     {
    //       pass_hash += file_data[16 + uname_length + j+use_size];
    //     }
        
    //     unsigned int content_length = 0; 
    //     for(int i =0; i <4; i++)
    //     {
    //       content_length |= ((unsigned int)file_data[16+i+uname_length+pass_hash_length+use_size] << 8*i);
    //     }
        
    //     string content;
    //     vector <uint8_t> content_use;
    //     for(int j = 0; j < static_cast<int>(content_length); j++)
    //     {

    //       content += file_data[20 + uname_length + pass_hash_length + j+use_size];
    //       content_use.push_back(file_data[20 + uname_length + pass_hash_length + j+use_size]);
    //     }
        
    //     use_size+=20+uname_length+pass_hash_length+content_length;
    //     vector<uint8_t> vecPass = vector<uint8_t>(pass_hash.begin(), pass_hash.end());
    //     struct AuthTableEntry entry = {uname, vecPass, content_use};
      
    //     auth_table->insert(uname, entry);

    //   }
    //   else if(header.compare("KVKVKVKV") == 0)
    //   {
    //     //Now will be able to make the additions for the kv-store update
    //     unsigned int key_length = 0;
    //     for(int i =0; i <4; i++)
    //     {
    //       key_length |= ((unsigned int)file_data[8 + i + use_size] << 8 * i);
    //     }

    //     string key;
    //     for(int j = 0; j < static_cast<int>(key_length); j++)
    //     {
    //       key += file_data[12 + j + use_size];
    //     }

    //     unsigned int value_length = 0; 
    //     for(int i =0; i <4; i++)
    //     {
    //       value_length |= ((unsigned int)file_data[12 + i + key_length + use_size] << 8 * i);
    //     }
        
    //     string value;
    //     vector<uint8_t> value_use;
    //     for(int j = 0; j < static_cast<int>(value_length); j++)
    //     {
    //       //content just for string printout
    //       value += file_data[16 + key_length + value_length + j + use_size];
    //       value_use.push_back(file_data[16 + key_length + value_length + j + use_size]);
    //     }

    //     //Now add back into data structure 
    //     use_size += 16 + key_length + value_length;
    //     kv_store->insert(key, value_use);
    //   }
    //   //Always clear the header string
    //   header.clear();

    // }
    
    // return true; 
  };
};

/// Create an empty Storage object and specify the file from which it should
/// be loaded.  To avoid exceptions and errors in the constructor, the act of
/// loading data is separate from construction.
///
/// @param fname   The name of the file to use for persistence
/// @param buckets The number of buckets in the hash table
/// @param upq     The upload quota
/// @param dnq     The download quota
/// @param rqq     The request quota
/// @param qd      The quota duration
/// @param top     The size of the "top keys" cache
/// @param admin   The administrator's username
Storage *storage_factory(const std::string &fname, size_t buckets, size_t upq,
                         size_t dnq, size_t rqq, double qd, size_t top,
                         const std::string &admin) {
  return new MyStorage(fname, buckets, upq, dnq, rqq, qd, top, admin);
}

#include <cassert>
#include <cstdio>
#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include "../common/contextmanager.h"
#include "../common/err.h"
#include "../common/file.h"
#include "../common/protocol.h"

#include "authtableentry.h"
#include "format.h"
#include "map.h"
#include "map_factories.h"
#include "persist.h"
#include "storage.h"

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

  /// The open file
  FILE *storage_file = nullptr;

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

    //check if username and password are the right length
    if (user.length() > LEN_UNAME || pass.length() > LEN_PASSWORD) 
      return {false, RES_ERR_LOGIN, {}};

    //salt for new user
    unsigned char salt[LEN_SALT];
    if (RAND_bytes(salt, LEN_SALT) == 0) { //returns 1 if success, 0 if failed
      return {false, RES_ERR_SERVER, {}};
    }
    vector<uint8_t> saltVector;
    for (size_t i = 0; i < LEN_SALT; i++) {
      saltVector.push_back(salt[i]);
    }

    //add salt to the password
    string saltedPassword = pass;
    for (size_t i = 0; i < LEN_SALT; i++) {
      saltedPassword.push_back(salt[i]);
    }

    //hash the salted password
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, saltedPassword.c_str(), saltedPassword.length());
    unsigned char hashedPassword[LEN_PASSHASH];
    EVP_DigestFinal_ex(ctx, hashedPassword, 0);

    vector<uint8_t> hashedPasswordVector;
    for (size_t i = 0; i < LEN_PASSHASH; i++) {
      hashedPasswordVector.push_back(hashedPassword[i]);
    }

    //new AuthTableEntry
    AuthTableEntry newUser;
    newUser.username = user;
    newUser.salt = saltVector;
    newUser.pass_hash = hashedPasswordVector;
    newUser.content = {};

    //lambda function for authtable entry
    auto authtable_entry = [&] () {
      vector<uint8_t> data_to_write;
      size_t user_len = user.size();
      size_t salt_len = saltVector.size();
      size_t pass_len = saltedPassword.size();
      size_t cont_len = 0; //no data yet

      data_to_write.insert(data_to_write.end(), AUTHENTRY.begin(), AUTHENTRY.end());

      //append data lengths to data_to_write
      data_to_write.insert(data_to_write.end(), (char*) &user_len, ((char*) &user_len) + sizeof(size_t));
      data_to_write.insert(data_to_write.end(), (char*) &salt_len, ((char*) &salt_len) + sizeof(size_t));
      data_to_write.insert(data_to_write.end(), (char*) &pass_len, ((char*) &pass_len) + sizeof(size_t));
      data_to_write.insert(data_to_write.end(), (char*) &cont_len, ((char*) &cont_len) + sizeof(size_t));

      //append data to data_to_write
      data_to_write.insert(data_to_write.end(), user.begin(), user.end());
      data_to_write.insert(data_to_write.end(), saltVector.begin(), saltVector.end());
      data_to_write.insert(data_to_write.end(), hashedPasswordVector.begin(), hashedPasswordVector.end());
      data_to_write.insert(data_to_write.end(), newUser.content.begin(), newUser.content.end());

      //add padding 
      size_t pad = 0;
      if (data_to_write.size() % 8 != 0) {
        size_t pads = 8 - (data_to_write.size() % 8);
        for (size_t i = 0; i < pads; i++) {
          data_to_write.push_back(pad);
        }
      }

      //add new data to storage_file
      storage_file = fopen(filename.c_str(), "a");
      if (storage_file != nullptr) {
        fwrite(data_to_write.data(), sizeof(uint8_t), data_to_write.size(), storage_file);
        fflush(storage_file);
        fsync(fileno(storage_file));
      }

    };

    //insert new data into auth_table
    if (auth_table->insert(user, newUser, authtable_entry)) {
      return {true, RES_OK, {}};             //new user inserted
    }
    return {false, RES_ERR_USER_EXISTS, {}}; //user already exists

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

    //authenticate user
    if (!auth(user, pass).succeeded)
      return result_t{false, RES_ERR_LOGIN, {}};

    //lambda function to set user data and create log entry
    auto set_data = [&] (AuthTableEntry entry) {
      entry.content = content;

      vector<uint8_t> data_to_write;
      size_t user_len = user.size();
      size_t cont_Len = content.size();

      data_to_write.insert(data_to_write.end(), AUTHDIFF.begin(), AUTHDIFF.end());

      //append data lengths
      data_to_write.insert(data_to_write.end(), (char*) &user_len, ((char*) &user_len) + sizeof(size_t));
      data_to_write.insert(data_to_write.end(), (char*) &cont_Len, ((char*) &cont_Len) + sizeof(size_t));

      //append data
      data_to_write.insert(data_to_write.end(), user.begin(), user.end());
      data_to_write.insert(data_to_write.end(), content.begin(), content.end());
      
      //add padding
      size_t pad = 0;
      if (data_to_write.size() % 8 > 0) {
        size_t pads = 8 - (data_to_write.size() % 8);
        for (size_t i = 0; i < pads; i++) {
          data_to_write.push_back(pad);
        }
      }

      //Add data to file
      storage_file = fopen(filename.c_str(), "a");
      if (storage_file != nullptr) {
        fwrite(data_to_write.data(), sizeof(uint8_t), data_to_write.size(), storage_file);
        fflush(storage_file);
        fsync(fileno(storage_file));
      }
    };

    if(auth_table->do_with(user, set_data)) {
      return {true, RES_OK, {}}; //content was updated
    } 
    return {false, RES_ERR_NO_USER, {}}; //Unable to update content

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
    
    //authenticate user
    if (!auth(user, pass).succeeded)
      return result_t{false, RES_ERR_LOGIN, {}};

    //lambda function to get user data
    vector<uint8_t> content;
    auto get_data = [&] (AuthTableEntry entry) {
      content = entry.content;
    };

    if(auth_table->do_with_readonly(who, get_data)) {
      if (content.size() > 0) {
        return {true, RES_OK, content};  //user exists and content fetched
      }
      return {false, RES_ERR_NO_DATA, {}}; //user exists but no content to be fetched
    }
    return {false, RES_ERR_NO_USER, {}};   //user doesn't exist

  }

  /// Return a newline-delimited string containing all of the usernames in the
  /// auth table
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t get_all_users(const string &user, const string &pass) {
    
    //authenticate user
    if (!auth(user, pass).succeeded)
      return result_t{false, RES_ERR_LOGIN, {}};

    //lambda function to get all usernames
    vector<uint8_t> all_usernames;
    auto get_all = [&] (string key, AuthTableEntry entry) {
      assert(key.size() > 0); //to remove compiler warning for not using key
      string username = entry.username;
      for (size_t i = 0; i < username.length(); i++) {
        all_usernames.push_back(username.at(i)); //rppend username to all_usernames list
      }
      all_usernames.push_back('\n');
    };

    //retrieve all  usernames
    auth_table->do_all_readonly(get_all, [](){});
    
    if (all_usernames.size() > 0) {
      return {true, RES_OK, {all_usernames}}; //got all usernames
    }
    return {false, RES_ERR_NO_DATA, {}}; //no users found

  }

  /// Authenticate a user
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t auth(const string &user, const string &pass) {
    
    //check if username and password are correct lengths
    if (user.length() > LEN_UNAME || pass.length() > LEN_PASSWORD)
      return {false, RES_ERR_LOGIN, {}};
    
    bool authenticated = false;

    //lambda function to authenticate user
    auto authenticate_user = [&] (AuthTableEntry entry) {
      string salt;
      for (size_t i = 0; i < entry.salt.size(); i++) {
        salt.push_back(entry.salt.at(i));  //convert to string
      }

      //add salt to password
      string saltedPassword = pass + salt;

      //hash salted password
      EVP_MD_CTX* ctx = EVP_MD_CTX_new();
      EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
      EVP_DigestUpdate(ctx, saltedPassword.c_str(), saltedPassword.length());
      unsigned char hashedPassword[LEN_PASSHASH];
      EVP_DigestFinal_ex(ctx, hashedPassword, 0);

      vector<uint8_t> hashedPasswordVector;
      for (size_t i = 0; i < LEN_PASSHASH; i++) {
        hashedPasswordVector.push_back(hashedPassword[i]); //convert to vector
      }

      //hashed password with user's hashed password
      bool matches = true;
      if (hashedPasswordVector.size() != entry.pass_hash.size()) {
        matches = false;
      }
      else {
        for (size_t i = 0; i < hashedPasswordVector.size(); i++) {
          if (hashedPasswordVector.at(i) != entry.pass_hash.at(i)) {
            matches = false;
          }
        }
      }
      authenticated = matches;
    };

    auth_table->do_with_readonly(user, authenticate_user);

    if (authenticated) {
      return {true, RES_OK, {}}; //user authenticated
    }
    return {false, RES_ERR_LOGIN, {}}; //User not authenticated

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

    //authenticate user
    if (!auth(user, pass).succeeded)
      return result_t{false, RES_ERR_LOGIN, {}};

    //lambda function for authtable entry
    auto authtable_insert = [&] () {
      vector<uint8_t> data_to_write;
      size_t key_len = key.size();
      size_t val_len = val.size();

      //Append KV constant
      data_to_write.insert(data_to_write.end(), KVENTRY.begin(), KVENTRY.end());

      //Append data lengths
      data_to_write.insert(data_to_write.end(), (char*) &key_len, ((char*) &key_len) + sizeof(size_t));
      data_to_write.insert(data_to_write.end(), (char*) &val_len, ((char*) &val_len) + sizeof(size_t));

      //Append data
      data_to_write.insert(data_to_write.end(), key.begin(), key.end());
      data_to_write.insert(data_to_write.end(), val.begin(), val.end());

      //add padding 
      size_t pad = 0;
      if (data_to_write.size() % 8 > 0) {
        size_t pads = 8 - (data_to_write.size() % 8);
        for (size_t i = 0; i < pads; i++) {
          data_to_write.push_back(pad);
        }
      }

      //Add data to storage_file
      storage_file = fopen(filename.c_str(), "a");
      if (storage_file != nullptr) {
        fwrite(data_to_write.data(), sizeof(uint8_t), data_to_write.size(), storage_file);
        fflush(storage_file);
        fsync(fileno(storage_file));
      }

    };

    //Insert key and value 
    if (kv_store->insert(key, val, authtable_insert)) {
      return {true, RES_OK, {}}; //value inserted
    }
    return {false, RES_ERR_KEY, {}}; //key already exists

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
    
    //authenticate user
    if (!auth(user, pass).succeeded)
      return result_t{false, RES_ERR_LOGIN, {}};

    //lambda function to get value
    vector<uint8_t> val;
    auto get_data = [&] (vector<uint8_t> vec) {
      val = vec;
    };

    if(kv_store->do_with_readonly(key, get_data)) {
      return {true, RES_OK, {val}}; //key exists and value fetched
    }
    return {false, RES_ERR_KEY, {}}; //invalid key

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
    
    //authenticate user
    if (!auth(user, pass).succeeded)
      return result_t{false, RES_ERR_LOGIN, {}};

    //Setup lambda function for authtbale entry
    auto delete_value = [&] () {
      vector<uint8_t> data_to_write;
      size_t key_len = key.size();

      
      data_to_write.insert(data_to_write.end(), KVDELETE.begin(), KVDELETE.end()); //append KVDELETE constant
      data_to_write.insert(data_to_write.end(), (char*) &key_len, ((char*) &key_len) + sizeof(size_t)); //append key length
      data_to_write.insert(data_to_write.end(), key.begin(), key.end()); //append key

      //Add padding 
      size_t pad = 0;
      if (data_to_write.size() % 8 > 0) {
        size_t pads = 8 - (data_to_write.size() % 8);
        for (size_t i = 0; i < pads; i++) {
          data_to_write.push_back(pad);
        }
      }

      //Add data to storage_file
      storage_file = fopen(filename.c_str(), "a");
      if (storage_file != nullptr) {
        fwrite(data_to_write.data(), sizeof(uint8_t), data_to_write.size(), storage_file);
        fflush(storage_file);
        fsync(fileno(storage_file));
      }

    };

    //Delete key and value
    if (kv_store->remove(key, delete_value)) {
      return {true, RES_OK, {}}; // key/value mapping deleted
    }
    return {false, RES_ERR_KEY, {}}; //key not found or error deleting mapping

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
    
    //authenticate user
    if (!auth(user, pass).succeeded)
      return result_t{false, RES_ERR_LOGIN, {}};

    //lambda function for insert
    auto insert_data = [&] () {
      vector<uint8_t> data_to_write;
      size_t key_len = key.size();
      size_t val_len = val.size();

      //append KV constant
      data_to_write.insert(data_to_write.end(), KVENTRY.begin(), KVENTRY.end());

      //append data lengths
      data_to_write.insert(data_to_write.end(), (char*) &key_len, ((char*) &key_len) + sizeof(size_t));
      data_to_write.insert(data_to_write.end(), (char*) &val_len, ((char*) &val_len) + sizeof(size_t));

      //append data
      data_to_write.insert(data_to_write.end(), key.begin(), key.end());
      data_to_write.insert(data_to_write.end(), val.begin(), val.end());

      //add padding 
      size_t pad = 0;
      if (data_to_write.size() % 8 > 0) {
        size_t pads = 8 - (data_to_write.size() % 8);
        for (size_t i = 0; i < pads; i++) {
          data_to_write.push_back(pad);
        }
      }

      //add data to storage_file
      storage_file = fopen(filename.c_str(), "a");
      if (storage_file != nullptr) {
        fwrite(data_to_write.data(), sizeof(uint8_t), data_to_write.size(), storage_file);
        fflush(storage_file);
        fsync(fileno(storage_file));
      }
    };

    //lambda function for update
    auto lambda_log_update = [&] () {
      vector<uint8_t> data_to_write;
      size_t key_len = key.size();
      size_t val_len = val.size();

      //append KVUPDATE constant
      data_to_write.insert(data_to_write.end(), KVUPDATE.begin(), KVUPDATE.end());

      //append data lengths
      data_to_write.insert(data_to_write.end(), (char*) &key_len, ((char*) &key_len) + sizeof(size_t));
      data_to_write.insert(data_to_write.end(), (char*) &val_len, ((char*) &val_len) + sizeof(size_t));

      //append data
      data_to_write.insert(data_to_write.end(), key.begin(), key.end());
      data_to_write.insert(data_to_write.end(), val.begin(), val.end());

      //add padding
      size_t pad = 0;
      if (data_to_write.size() % 8 > 0) {
        size_t pads = 8 - (data_to_write.size() % 8);
        for (size_t i = 0; i < pads; i++) {
          data_to_write.push_back(pad);
        }
      }

      //add data to storage_file
      storage_file = fopen(filename.c_str(), "a");
      if (storage_file != nullptr) {
        fwrite(data_to_write.data(), sizeof(uint8_t), data_to_write.size(), storage_file);
        fflush(storage_file);
        fsync(fileno(storage_file));
      }

    };

    //insert/update key and value into map
    if (kv_store->upsert(key, val, insert_data, lambda_log_update)) {
      return {true, RES_OKINS, {}}; //value inserted
    }
    return {true, RES_OKUPD, {}};   //value updated

  };

  /// Return all of the keys in the kv_store, as a "\n"-delimited string
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_all(const string &user, const string &pass) {

    //authenticate the user
    if (!auth(user, pass).succeeded)
      return result_t{false, RES_ERR_LOGIN, {}};

    //lambda function to get all keys
    vector<uint8_t> all_keys;
    auto get_all = [&] (string key, vector<uint8_t> val) { 
      assert(val.size() > 0); //val is ignored because we're only returning keys

      //append each key to all_keys
      for (size_t i = 0; i < key.length(); i++) {
        all_keys.push_back(key.at(i));
      }
      all_keys.push_back('\n');
    };

    //retrieve all keys
    kv_store->do_all_readonly(get_all, [] () {});
    
    if (all_keys.size() > 0) {
      return {true, RES_OK, {all_keys}}; //got all keys
    }
    return {false, RES_ERR_NO_DATA, {}}; //no keys found

  };

  /// Shut down the storage when the server stops.  This method needs to close
  /// any open files related to incremental persistence.  It also needs to clean
  /// up any state related to .so files.  This is only called when all threads
  /// have stopped accessing the Storage object.
  virtual void shutdown() {
    fflush(storage_file);
    fsync(fileno(storage_file));
    fclose(storage_file);
  }

  /// Write the entire Storage object to the file specified by this.filename. To
  /// ensure durability, Storage must be persisted in two steps.  First, it must
  /// be written to a temporary file (this.filename.tmp).  Then the temporary
  /// file can be renamed to replace the older version of the Storage object.
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t save_file() {

    //lambda function to save auth table entries
    vector<uint8_t> authTable;
    auto authtable_get_all = [&] (string name, AuthTableEntry entry) {
      size_t user_len = name.size();
      size_t salt_len = entry.salt.size();
      size_t pass_len = entry.pass_hash.size();
      size_t cont_len = entry.content.size();

      //Add AUTHAUTH Constant
      authTable.insert(authTable.end(), AUTHENTRY.begin(), AUTHENTRY.end());

      //append data lengths
      authTable.insert(authTable.end(), (char*) &user_len, ((char*) &user_len) + sizeof(size_t));
      authTable.insert(authTable.end(), (char*) &salt_len, ((char*) &salt_len) + sizeof(size_t));
      authTable.insert(authTable.end(), (char*) &pass_len, ((char*) &pass_len) + sizeof(size_t));
      authTable.insert(authTable.end(), (char*) &cont_len, ((char*) &cont_len) + sizeof(size_t));

      //append data
      authTable.insert(authTable.end(), name.begin(), name.end());
      authTable.insert(authTable.end(), entry.salt.begin(), entry.salt.end());
      authTable.insert(authTable.end(), entry.pass_hash.begin(), entry.pass_hash.end());
      authTable.insert(authTable.end(), entry.content.begin(), entry.content.end());

      //add padding 
      size_t pad = 0;
      if (authTable.size() % 8 > 0) {
        size_t pads = 8 - (authTable.size() % 8);
        for (size_t i = 0; i < pads; i++) {
          authTable.push_back(pad);
        }
      }
    };

    //lambda function to save KV store entries
    vector<uint8_t> kvStore;
    auto kvstore_get_all = [&] (string k, vector<uint8_t> v) {
      size_t key_len = k.size();
      size_t val_len = v.size();

      //append KVKVKVKV Constant
      kvStore.insert(kvStore.end(), KVENTRY.begin(), KVENTRY.end());

      //append data lengths
      kvStore.insert(kvStore.end(), (char*) &key_len, ((char*) &key_len) + sizeof(size_t));
      kvStore.insert(kvStore.end(), (char*) &val_len, ((char*) &val_len) + sizeof(size_t));

      //append data
      kvStore.insert(kvStore.end(), k.begin(), k.end());
      kvStore.insert(kvStore.end(), v.begin(), v.end());

      //add padding
      size_t pad = 0;
      if (kvStore.size() % 8 > 0) {
        size_t pads = 8 - (kvStore.size() % 8);
        for (size_t i = 0; i < pads; i++) {
          kvStore.push_back(pad);
        }
      }
    };

    //lambda function for chaining of auth table and KV store
    auto lambda_chain = [&] () {
      kv_store->do_all_readonly(kvstore_get_all, [] () {});
    };

    auth_table->do_all_readonly(authtable_get_all, lambda_chain);

    //append kvStore to authTable
    authTable.insert(authTable.end(), kvStore.begin(), kvStore.end());

    //write to the temp file, then rename it
    if (write_file(filename + ".tmp", authTable, 0)) {
      rename((filename + ".tmp").c_str(), filename.c_str());
      return {true, RES_OK, {}};
    }

    return {false, RES_ERR_SERVER, {}};
    
  }

  /// Populate the Storage object by loading this.filename.  Note that load()
  /// begins by clearing the maps, so that when the call is complete, exactly
  /// and only the contents of the file are in the Storage object.
  ///
  /// @return A result tuple, as described in storage.h.  Note that a
  ///         non-existent file is not an error.
  virtual result_t load_file() {
    storage_file = fopen(filename.c_str(), "r");
    if (storage_file == nullptr) {
      return {true, "File not found: " + filename, {}};
    }
    
    //clear both maps
    auth_table->clear();
    kv_store->clear();

    vector<uint8_t> contents = load_entire_file(filename);

    //loop through file contents
    size_t index = 0;
    while (index < contents.size()) {
      string header;
      for (size_t i = 0; i < 8; i++) {
        header += contents.at(index);
        index += 1;
      }
    //authentry
      if (header.compare(AUTHENTRY) == 0) {
        size_t user_len = *(size_t*) (contents.data() + index); //username length
        index += 8;
        size_t salt_len = *(size_t*) (contents.data() + index); //salt length
        index += 8;
        size_t pass_len = *(size_t*) (contents.data() + index); //hashed password length
        index += 8;
        size_t cont_len = *(size_t*) (contents.data() + index); //content length
        index += 8;

        string username;
        vector<uint8_t> salt;
        vector<uint8_t> hashedPassword;
        vector<uint8_t> profile;

        for (size_t i = 0; i < user_len; i++) { //get the username
          username += contents[index];
          index += 1;
        }
        for (size_t i = 0; i < salt_len; i++) { //get the salt
          salt.push_back(contents[index]);
          index += 1;
        }
        for (size_t i = 0; i < pass_len; i++) {//get the hashed password
          hashedPassword.push_back(contents[index]);
          index += 1;
        }
        if (cont_len > 0) {
          for (size_t i = 0; i < cont_len; i++) { //get the profile content
            profile.push_back(contents[index]);
            index += 1;
          }
        }
        
        if (index % 8 > 0) { //find number of pads
          index += (8 - (index % 8));
        }

        //create AuthTableEntry
        AuthTableEntry authTableEntry;
        authTableEntry.username = username;
        authTableEntry.salt = salt;
        authTableEntry.pass_hash = hashedPassword;
        if (cont_len > 0) {
          authTableEntry.content = profile;
        }
        else {
          authTableEntry.content = {};
        }
        //insert into auth table
        auth_table->insert(username, authTableEntry, [] () {});
      }

    //KVENTRY
      else if (header.compare(KVENTRY) == 0) {
        size_t key_len = *(size_t*) (contents.data() + index); //get key length
        index += 8;
        size_t val_len = *(size_t*) (contents.data() + index); //get value length
        index += 8;

        string key;
        vector<uint8_t> value;

        for (size_t i = 0; i < key_len; i++) { //get the key
          key += contents[index];
          index += 1;
        }
        for (size_t i = 0; i < val_len; i++) { //get the value 
          value.push_back(contents[index]);
          index += 1;
        }

        if (index % 8 > 0) { //find number of pads
          size_t pads = 8 - (index % 8);
          index += pads;
        }
        
        kv_store->insert(key, value, [] () {}); //insert into KV store
      }

      //AUTHDIFF
      else if (header.compare(AUTHDIFF) == 0) {
        size_t user_len = *(size_t*) (contents.data() + index); //get username length
        index += 8;
        size_t cont_len = *(size_t*) (contents.data() + index); //get content length
        index += 8;

        
        string username;
        vector<uint8_t> profile;

        for (size_t i = 0; i < user_len; i++) { //fet the username
          username += contents[index];
          index += 1;
        }
        for (size_t i = 0; i < cont_len; i++) { //get the profile content
          profile.push_back(contents[index]);
          index += 1;
        }

        if (index % 8 > 0) { //find number of pads
          size_t pads = 8 - (index % 8);
          index += pads;
        }
        //lambda function to update user content
        auto lambda_update = [&] (AuthTableEntry entry) {
          entry.content = profile;
        };
        
        auth_table->do_with(username, lambda_update); //update authtable
      }

    //KVUPDATE
      else if (header.compare(KVUPDATE) == 0) {
        size_t keyLength = *(size_t*) (contents.data() + index); //get the key length
        index += 8;
        size_t valueLength = *(size_t*) (contents.data() + index); //get the value length
        index += 8;

        string key;
        vector<uint8_t> value;

        for (size_t i = 0; i < keyLength; i++) { //get the key
          key += contents[index];
          index += 1;
        }
        for (size_t i = 0; i < valueLength; i++) { //get the value
          value.push_back(contents[index]);
          index += 1;
        }

        
        if (index % 8 > 0) { //find number of pads
          size_t pads = 8 - (index % 8);
          index += pads;
        }
        
        kv_store->upsert(key, value, [](){}, [](){}); //update KV store
      }

    //KVDELETE
      else if (header.compare(KVDELETE) == 0) {
        size_t key_len = *(size_t*) (contents.data() + index); //get the key lengt
        index += 8;
        string key;
        for (size_t i = 0; i < key_len; i++) { //get the key
          key += contents[index];
          index += 1;
        }
        
        if (index % 8 > 0) { //find number of pads
          size_t pads = 8 - (index % 8);
          index += pads;
        }
        
        kv_store->remove(key, [](){}); //remove from KV store
      }
    }
    return {true, "Loaded: " + filename , {}};
    
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
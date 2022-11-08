#include <cassert>
#include <cstdio>
#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include "../common/contextmanager.h"
#include "../common/err.h"
#include "../common/protocol.h"

#include "authtableentry.h"
#include "format.h"
#include "helpers.h"
#include "map.h"
#include "map_factories.h"
#include "mru.h"
#include "persist.h"
#include "quotas.h"
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

  /// The upload quota
  const size_t up_quota;

  /// The download quota
  const size_t down_quota;

  /// The requests quota
  const size_t req_quota;

  /// The number of seconds over which quotas are enforced
  const double quota_dur;

  /// The table for tracking the most recently used keys
  mru_manager *mru;

  /// A table for tracking quotas
  Map<string, Quotas *> *quota_table;

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
  MyStorage(const std::string &fname, size_t buckets, size_t upq, size_t dnq,
            size_t rqq, double qd, size_t top, const std::string &)
      : auth_table(authtable_factory(buckets)),
        kv_store(kvstore_factory(buckets)), filename(fname), up_quota(upq),
        down_quota(dnq), req_quota(rqq), quota_dur(qd), mru(mru_factory(top)),
        quota_table(quotatable_factory(buckets)) {}

  /// Destructor for the storage object.
  virtual ~MyStorage() {
    // TODO: you probably want to free some memory here...
    auth_table->clear();
    delete auth_table;
    kv_store->clear();
    delete kv_store;
    mru->clear();
    delete mru;
    quota_table->clear();
    delete quota_table;
  }






  /*                              USER METHODS                                */
  /*--------------------------------------------------------------------------*/






  /// Create a new entry in the Auth table.  If the user already exists, return
  /// an error.  Otherwise, create a salt, hash the password, and then save an
  /// entry with the username, salt, hashed password, and a zero-byte content.
  ///
  /// @param user The user name to register
  /// @param pass The password to associate with that user name
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t add_user(const string &user, const string &pass) {

    Quotas *quotas = new Quotas();
    quotas->uploads = quota_factory(up_quota,quota_dur) ;
    quotas->downloads  = quota_factory(down_quota,quota_dur) ;
    quotas->requests  = quota_factory(req_quota,quota_dur) ;

    // insert user quota into quota_table
    bool insert_success = quota_table->insert(user,quotas, [](){} );
    if(!insert_success) delete quotas;

    return add_user_helper(user, pass, auth_table, storage_file);
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
    // NB: the helper (.o provided) does all the work for this operation :)
    return set_user_data_helper(user, pass, content, auth_table, storage_file);
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
    // NB: the helper (.o provided) does all the work for this operation :)
    return get_user_data_helper(user, pass, who, auth_table);
  }

  /// Return a newline-delimited string containing all of the usernames in the
  /// auth table
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t get_all_users(const string &user, const string &pass) {
    // NB: the helper (.o provided) does all the work for this operation :)
    return get_all_users_helper(user, pass, auth_table);
  }

  /// Authenticate a user
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t auth(const string &user, const string &pass) {
    // NB: the helper (.o provided) does all the work for this operation :)
    return auth_helper(user, pass, auth_table);
  }






  /*                              HELPER METHODS                              */
  /*--------------------------------------------------------------------------*/



  bool validRequest(const string &user) {
    bool valid_request = false ;
    quota_table->do_with(user, [&](Quotas *quota ){
      valid_request = quota->requests->check_add(1);
    });
    return valid_request;
  }

  bool validUpload(const string &user, const vector<uint8_t> &val){
    bool valid_upload = false;
    quota_table->do_with(user, [&](Quotas *quota ){
      valid_upload = quota->uploads->check_add(val.size());
    });
    return valid_upload;
  }

  bool validDownload(const string &user, vector<uint8_t> content){
    bool valid_download = false;
    quota_table->do_with(user, [&](Quotas *quota ){
      valid_download = quota->downloads->check_add(content.size());
    });
    return valid_download;
  }









  /*                              KV METHODS                                  */
  /*--------------------------------------------------------------------------*/



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
    // authenticate user and password
    if(!auth(user, pass).succeeded){  return result_t {true, RES_ERR_LOGIN, {}}; }

    // writes KV pair to storage file
    auto printKVStuff = [&] (){
      vector<uint8_t> data_to_write;
      size_t key_len = key.size();
      size_t val_len = val.size();
      //Append KV constant
      data_to_write.insert(data_to_write.end(), REQ_KVI.begin(), REQ_KVI.end());
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

    //check request and upload quota 
    if (!validRequest(user)) return {false, RES_ERR_QUOTA_REQ, {}};
    if (!validUpload(user, val)) return {false, RES_ERR_QUOTA_UP, {}};

    // check for insert success
    if (kv_store->insert(key, val, printKVStuff)) { 
        this->mru->insert(key);
        return {true, RES_OK, {}};
    }
    return result_t{false, RES_ERR_KEY, {}};
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
    // authenticate user and password
    if (!auth(user, pass).succeeded) { return {false, RES_ERR_LOGIN, {}}; }

    //check request quota
    if (!validRequest(user)) return {false, RES_ERR_QUOTA_REQ, {}};
 
    // vector to store kv data
    vector<uint8_t> content; 
    auto getData = [&] (vector<uint8_t> value) {
        content = value;    
    };                 
    kv_store->do_with_readonly(key, getData);

    // check download quota
    if (!validDownload(user, content)) { return {false, RES_ERR_QUOTA_DOWN, {}}; }
    
    // check if key value exists
    if (content.size() != 0) {
      this->mru->insert(key);
      return {true, RES_OK, content};
    }
    return {false, RES_ERR_KEY, {content}};
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
    //authenticate username and password
    if (!(auth(user, pass).succeeded)) { return {false, RES_ERR_LOGIN, {}}; }

    // check request quota
    if(!validRequest(user)) { return {false, RES_ERR_QUOTA_REQ, {}}; }

    // write to remove KV pair from the file
    auto removeKVData = [&] (){
      vector<uint8_t> data_to_write;
      size_t key_len = key.size();
      //Append KV constant
      data_to_write.insert(data_to_write.end(), REQ_KVD.begin(), REQ_KVD.end());
      //Append data lengths
      data_to_write.insert(data_to_write.end(), (char*) &key_len, ((char*) &key_len) + sizeof(size_t));
      //Append data
      data_to_write.insert(data_to_write.end(), key.begin(), key.end());
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

    //remove key from kv_store
    if (!kv_store->remove(key, removeKVData)) { return {true, RES_ERR_KEY, {}}; }
    else {
      this->mru->remove(key);
      return {true, RES_OK, {}};
    }
  };

  /// Insert or update, so that the given key is mapped to the give value
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  /// @param key  The key whose mapping is being upserted
  /// @param val  The value to copy into the map
  ///
  /// @return A result tuple, as described in storage.h.  Note that there are
  /// two
  ///         "OK" messages, depending on whether we get an insert or an update.
  virtual result_t kv_upsert(const string &user, const string &pass,
                             const string &key, const vector<uint8_t> &val) {
    // authenticate user                            
    if(!auth(user, pass).succeeded){ return {false, RES_ERR_LOGIN, {}};  } 

    // check request and upload quota
    if (!validRequest(user)) {  return {false, RES_ERR_QUOTA_REQ, {}}; }
    if (!validUpload(user, val)) { return {false, RES_ERR_QUOTA_UP, {}}; }

    // lambda in the case of a key not already existing
    // insert key/value pairs into storage_file
    auto onIns = [&] (){
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
    
    // lambda in the case of key existing, replacing the value
    // insert key/value pairs into storage_file
    auto onUpd = [&] (){
      vector<uint8_t> data_to_write;
      size_t key_len = key.size();
      size_t val_len = val.size();
      //Append KV constant
      data_to_write.insert(data_to_write.end(), KVUPDATE.begin(), KVUPDATE.end());
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

    //  specifies if we've done an insertion or update
    if (kv_store->upsert(key, val, onIns, onUpd)) { 
      this->mru->insert(key);
      return {true, RES_OKINS, {}};
    }
    // update key in mru
    this->mru->insert(key);
    return {true, RES_OKUPD, {}};
  };

  /// Return all of the keys in the kv_store, as a "\n"-delimited string
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_all(const string &user, const string &pass) {

    // authenticate user
    if (!auth(user, pass).succeeded) { return result_t{false, RES_ERR_LOGIN, {}}; }

    // check request quota
    if (!validRequest(user)) { return {false, RES_ERR_QUOTA_REQ, {}}; }

    // lamda function
    vector<uint8_t> allUsers;
    function<void(string, const vector<uint8_t>&)> kv_all_vec = [&](string user, const vector<uint8_t> &) {
      // insert new line character before each user
      user += '\n';
      vector<uint8_t>userVec(user.begin(), user.end());
      allUsers.insert(allUsers.end(), userVec.begin(), userVec.end());
    };
    kv_store->do_all_readonly(kv_all_vec, [&](){});
    
    // check if any users exists
    if (allUsers.size() == 0) { return {false, RES_ERR_NO_DATA, {allUsers}}; }

    // check download quota
    if(validDownload(user, allUsers)) { return {true, RES_OK, allUsers}; }

    return {false, RES_ERR_QUOTA_DOWN, {}};
  };

  /// Return all of the keys in the kv_store's MRU cache, as a "\n"-delimited
  /// string
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_top(const string &user, const string &pass) {
    
    // authenticate user
    if (!auth(user, pass).succeeded) { return result_t{ false, RES_ERR_LOGIN, {}}; }

    // check request quota
    if(!validRequest(user)) { return {false, RES_ERR_QUOTA_REQ, {}}; }

    // get keys as string from mru 
    string keyStr = this->mru->get();
    // check if there are any keys
    if (keyStr == ""){
      return {false, RES_ERR_NO_DATA, {}};
    }
    // convert to a vector
    vector<uint8_t> keyVec (keyStr.begin(), keyStr.end());

    // check if download is larger than what quota table can handle
    if(!validDownload(user, keyVec)) { return {false, RES_ERR_QUOTA_DOWN, {}}; }
    
    return {true, RES_OK, keyVec}; 
  };










  /// Shut down the storage when the server stops.  This method needs to close
  /// any open files related to incremental persistence.  It also needs to clean
  /// up any state related to .so files.  This is only called when all threads
  /// have stopped accessing the Storage object.
  virtual void shutdown() {
    // NB: Based on how the other methods are implemented in the helper file, we
    //     need this command here:
    fclose(storage_file);
  }

  /// Write the entire Storage object to the file specified by this.filename. To
  /// ensure durability, Storage must be persisted in two steps.  First, it must
  /// be written to a temporary file (this.filename.tmp).  Then the temporary
  /// file can be renamed to replace the older version of the Storage object.
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t save_file() {
    // NB: the helper (.o provided) does all the work for this operation :)
    return save_file_helper(auth_table, kv_store, filename, storage_file);
  }

  /// Populate the Storage object by loading this.filename.  Note that load()
  /// begins by clearing the maps, so that when the call is complete, exactly
  /// and only the contents of the file are in the Storage object.
  ///
  /// @return A result tuple, as described in storage.h.  Note that a
  /// non-existent
  ///         file is not an error.
  virtual result_t load_file() {
    // NB: the helper (.o provided) does all the work from p1/p2/p3 for this
    //     operation.  Depending on how you choose to implement quotas, you may
    //     need to edit this.
    return load_file_helper(auth_table, kv_store, filename, storage_file);
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

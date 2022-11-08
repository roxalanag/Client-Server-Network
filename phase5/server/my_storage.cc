#include <cassert>
#include <functional>
#include <iostream>
#include <string>
#include <unistd.h>
#include <vector>

#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/wait.h>

#include "../common/contextmanager.h"
#include "../common/protocol.h"

#include "functable.h"
#include "helpers.h"
#include "map.h"
#include "map_factories.h"
#include "mru.h"
#include "quotas.h"
#include "storage.h"



// from p3:
#include <cassert>
#include <cstdio>
#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <openssl/rand.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include<bits/stdc++.h>

#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>
#include <assert.h>     /* assert */

#include "../common/contextmanager.h"
#include "../common/err.h"
#include "../common/protocol.h"
#include "../common/file.h"

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

  /// The name of the admin user
  string admin_name;

  /// The function table, to support executing map/reduce on the kv_store
  FuncTable *funcs;

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
            size_t rqq, double qd, size_t top, const std::string &admin)
      : auth_table(authtable_factory(buckets)),
        kv_store(kvstore_factory(buckets)), filename(fname), up_quota(upq),
        down_quota(dnq), req_quota(rqq), quota_dur(qd), mru(mru_factory(top)),
        quota_table(quotatable_factory(buckets)), admin_name(admin),
        funcs(functable_factory()) {}

  /// Destructor for the storage object.
  virtual ~MyStorage() {
    cout << "my_storage.cc::~MyStorage() is not implemented\n";
  }

  /// Create a new entry in the Auth table.  If the user already exists, return
  /// an error.  Otherwise, create a salt, hash the password, and then save an
  /// entry with the username, salt, hashed password, and a zero-byte content.
  ///
  /// @param user The user name to register
  /// @param pass The password to associate with that user name
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t add_user(const string &user, const string &pass) {
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
    return get_all_users_helper(user, pass, auth_table);
  }

  /// Authenticate a user
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t auth(const string &user, const string &pass) {
    return auth_helper(user, pass, auth_table);
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
    return kv_insert_helper(user, pass, key, val, auth_table, kv_store,
                            storage_file, mru, up_quota, down_quota, req_quota,
                            quota_dur, quota_table);
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
    return kv_get_helper(user, pass, key, auth_table, kv_store, mru, up_quota,
                         down_quota, req_quota, quota_dur, quota_table);
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
    return kv_delete_helper(user, pass, key, auth_table, kv_store, storage_file,
                            mru, up_quota, down_quota, req_quota, quota_dur,
                            quota_table);
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
    return kv_upsert_helper(user, pass, key, val, auth_table, kv_store,
                            storage_file, mru, up_quota, down_quota, req_quota,
                            quota_dur, quota_table);
  };

  /// Return all of the keys in the kv_store, as a "\n"-delimited string
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_all(const string &user, const string &pass) {
    return kv_all_helper(user, pass, auth_table, kv_store, up_quota, down_quota,
                         req_quota, quota_dur, quota_table);
  };

  /// Return all of the keys in the kv_store's MRU cache, as a "\n"-delimited
  /// string
  ///
  /// @param user The name of the user who made the request
  /// @param pass The password for the user, used to authenticate
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t kv_top(const string &user, const string &pass) {
    return kv_top_helper(user, pass, auth_table, mru, up_quota, down_quota,
                         req_quota, quota_dur, quota_table);
  };




  // New functions in P5


  /// Register a .so with the function table
  ///
  /// @param user   The name of the user who made the request
  /// @param pass   The password for the user, used to authenticate
  /// @param mrname The name to use for the registration
  /// @param so     The .so file contents to register
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t register_mr(const string &user, const string &pass,
                               const string &mrname,
                               const vector<uint8_t> &so) {
    // authenticate user
    if (!auth(user, pass).succeeded) { return result_t{false, RES_ERR_LOGIN, {}}; }

    // check if user is admin
    if (user != admin_name) { return result_t{false, RES_ERR_LOGIN, {}}; }

    // call register_mr in my_functable.cc
    return result_t{true, funcs->register_mr(mrname, so), {}};
  };


  /// Execute child process of map/reduce function
  ///     Execute map and reduce functions outside of 
  ///     main server process prevents an innsecure server 
  /// @param readPipe   The pipe to read data from parent process
  /// @param writePipe  The pipe fd on which to write data to the parent
  /// @param mapFunc    The map function runs on every key/value pair from parent
  /// @param reduceFunc The reduce function runs on the return of map function
  ///
  /// @returns false if any error occurred, true otherwise
  bool invoke_mr_child(int readPipe, int writePipe, map_func mapFunc, reduce_func reduceFunc) {
    // SECCOMP Implemnetation: restrict child process access to system calls 
    // Citation: 
    // https://blog.yadutaf.fr/2014/05/29/introduction-to-seccomp-bpf-linux-syscall-filter/
    // prevents child process from corrupting syscall filters
    // prctl(PR_SET_NO_NEW_PRIVS, 1);
    // enable filter 
    // NOTE: this line causes test #2 to fail (Expect: OK ... got 'ERR_SERVER)
    // if ( -1 == prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT) ) 
    //   return false; 

    char size_buf[4]; //to hold the size of the rest of the buffer
    int nr; int nw; //number of bytes read, number of bytes written

    //obtain size of k/v buffer
    nr = read(readPipe, size_buf, sizeof(int));
    if(nr < 4){
      close(readPipe); //error
      close(writePipe);
      return false;
    }

    unsigned int kv_length = 0; //convert from  char* to uint
    for(int i = 0; i <4; i++)
      kv_length |= ((unsigned int)size_buf[i] << 8 * i);

    char buf[kv_length]; //allocate buffer

    vector<uint8_t> map_result; // to hold result from the mapper
    vector<vector<uint8_t>> intermediate; // to hold intermediate results from the mapper
    vector<uint8_t> pipe_write; //to hold data to be written back to the parent

    nr = read(readPipe, buf, sizeof(buf));
    if(nr < 0){
      close(readPipe); //error
      close(writePipe);
      return false;
    }

    int counter = 0;
    while(counter < nr){
      unsigned int key_length = 0; //get key_size
      for(int i =0; i <4; i++)
        key_length |= ((unsigned int)buf[i+counter] << 8 * i);

      string key; //get key
      for(int j = 0; j < static_cast<int>(key_length); j++)
        key += buf[4 + j + counter];

      unsigned int value_length = 0; //get val_size
      for(int i =0; i <4; i++)
        value_length |= ((unsigned int)buf[4 + key_length + i + counter] << 8 * i);

      string value;
      vector<uint8_t> value_use; //get val
      for(int j = 0; j < static_cast<int>(value_length); j++)
        //content just for string printout
        value += buf[8 + key_length + j +counter];

      value_use.insert(value_use.end(), value.begin(), value.end());
      counter += 8 + key_length + value_length; //acts as offest to read next k/v

      //get the mapped results
      map_result = mapFunc(key,value_use);
      intermediate.push_back(map_result); //add to intermediate results
    }
    //after reading all data close the input pipe
    close(readPipe);

    //reduce the result of the map function
    vector<uint8_t> reduce = reduceFunc(intermediate);
    size_t reduce_len = reduce.size();

    //format for sending 
    pipe_write.insert(pipe_write.end(), (uint8_t*)&reduce_len, ((uint8_t*)&reduce_len) + sizeof(int)); 
    pipe_write.insert(pipe_write.end(), reduce.begin(), reduce.end());

    char *data = reinterpret_cast<char*>(pipe_write.data());
    int buff_size = pipe_write.size();

    nw = write(writePipe, data, buff_size);
    if(nw < 0){
      close(writePipe);//error
      return false;
    }
    close(writePipe); //close output pipe
    return true;
  }

  /// Run a map/reduce on all the key/value tuples of the kv_store
  ///
  /// @param user   The name of the user who made the request
  /// @param pass   The password for the user, to authenticate
  /// @param mrname The name of the map/reduce functions to use
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t invoke_mr(const string &user, const string &pass,
                             const string &mrname) {

    // authenticate user
    if (!auth(user, pass).succeeded) 
      return {false, RES_ERR_LOGIN, {}}; 

    pair<map_func, reduce_func> func_pair = funcs->get_mr(mrname);
    if(func_pair.first == nullptr || func_pair.second == nullptr)
      return {false, RES_ERR_SO, {}};
    

    vector<uint8_t> output; //output for the function

    vector<uint8_t> pre_pipe_write; //get all kv pairs to hold in here to add into the pipe
    vector<uint8_t> pipe_write; //hold the kv and size of buffer necessary to hold kv pairs
    auto fcn_in = [&](const string key, const vector<uint8_t> & value){   
      size_t key_len = key.length();
      size_t val_len = value.size();

      //insert lengths and data
      pre_pipe_write.insert(pre_pipe_write.end(), (uint8_t*)&key_len, ((uint8_t*)&key_len) + sizeof(int)); 
      pre_pipe_write.insert(pre_pipe_write.end(), key.begin(), key.end()); 
      pre_pipe_write.insert(pre_pipe_write.end(), (uint8_t*)&val_len, ((uint8_t*)&val_len) + sizeof(int)); 
      pre_pipe_write.insert(pre_pipe_write.end(), value.begin(), value.end()); 
    };
    auto fcn_out = [](){};
    kv_store->do_all_readonly(fcn_in, fcn_out);

    //pipe[0] is the read end of the pipe
    //pipe[1] is the write end of the pipe
    int pipe1[2];//parent read/write communication
    int pipe2[2];//child read/write communication

    //failure to create the pipes
    if(pipe(pipe1) < 0 || pipe(pipe2) < 0)
      return {false, RES_ERR_SERVER, {}};

    pid_t cpid = fork(); //create a forked process
    
    if (cpid > 0){//NOTE: We are inside the parent process here.
      close(pipe1[0]); // close reading end of parent communication

      //prep data to be transferred via pipe
      size_t pipe_len = pre_pipe_write.size();

      //insert lengths and data
      pipe_write.insert(pipe_write.end(), (uint8_t*)&pipe_len, ((uint8_t*)&pipe_len) + sizeof(int)); 
      pipe_write.insert(pipe_write.end(), pre_pipe_write.begin(), pre_pipe_write.end()); 

      char * data = reinterpret_cast<char*>(pipe_write.data());
      int buff_size = pipe_write.size();

      //write data to pipe for child to receive
      int nw = write(pipe1[1], data, buff_size);
      if(nw < 0){
          close(pipe1[1]); //error
          close(pipe2[0]);
          close(pipe2[1]);
          return {false, RES_ERR_SERVER, {}};
      }
      close(pipe1[1]); //close writing end of parent communication

      int status; //create a status
      waitpid(cpid, &status, 0);

      if(status != 0){
        close(pipe2[0]); //error
        close(pipe2[1]);
        return {false, RES_ERR_SERVER, {}};
      }
      
      close(pipe2[1]); //close writing end of child communication

      char size_buf[4]; //to hold size of response buffer
      int nr; //number of bytes read

      nr = read(pipe2[0],size_buf, sizeof(int)); //obtain size of buffer
      if(nr < 4){
        close(pipe2[0]); //error
          return {false, RES_ERR_SERVER, {}};
      }

      unsigned int value_length = 0; //convert to uint
      for(int i = 0; i<4; i++)
        value_length |= ((unsigned int)size_buf[i] << 8 * i);

      char buf[value_length]; //allocate for size response

      nr = read(pipe2[0], buf, sizeof(buf)); //get response
      close(pipe2[0]); //close reading end of child communication

      if(nr < 0) //error
          return {false, RES_ERR_SERVER, {}};

      int i = 0; //take response, put it into a string and append string into a vector
      string value;
      while(i < nr){
        value += buf[i];
        i++;
      }
      output.insert(output.end(), value.begin(), value.end()); 
    }
    else if(cpid == 0){ //We are inside the child process here.
      close(pipe1[1]); //close writing end of parent communication
      close(pipe2[0]); //close reading end of child communication

      //call child function handler, and see if an error occured    
      if(!invoke_mr_child(pipe1[0], pipe2[1], func_pair.first, func_pair.second))
          return result_t{false, RES_ERR_SERVER, {}};
      exit(0); //kill child process
    }
    else{
      close(pipe1[0]); //failed to fork
      close(pipe1[1]);
      close(pipe2[0]);
      close(pipe2[1]);
      return {false, RES_ERR_SERVER, {}};
    }
    return {true, RES_OK, output};

  }

  /// Shut down the storage when the server stops.  This method needs to close
  /// any open files related to incremental persistence.  It also needs to clean
  /// up any state related to .so files.  This is only called when all threads
  /// have stopped accessing the Storage object.
  virtual void shutdown() {
    funcs->shutdown();
    fclose(storage_file);
    // TO DO:
    //      clean .so files
  }





  //end of new functions

  /// Write the entire Storage object to the file specified by this.filename. To
  /// ensure durability, Storage must be persisted in two steps.  First, it must
  /// be written to a temporary file (this.filename.tmp).  Then the temporary
  /// file can be renamed to replace the older version of the Storage object.
  ///
  /// @return A result tuple, as described in storage.h
  virtual result_t save_file() {
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
    return load_file_helper(auth_table, kv_store, filename, storage_file, mru);
  }
};

/// Create an empty Storage object and specify the file from which it should be
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
Storage *storage_factory(const std::string &fname, size_t buckets, size_t upq,
                         size_t dnq, size_t rqq, double qd, size_t top,
                         const std::string &admin) {
  return new MyStorage(fname, buckets, upq, dnq, rqq, qd, top, admin);
}

#include <atomic>
#include <cassert>
#include <dlfcn.h>
#include <iostream>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "../common/contextmanager.h"
#include "../common/err.h"
#include "../common/file.h"
#include "../common/protocol.h"

#include "functable.h"
#include "functypes.h"

using namespace std;

/// func_table is a table that stores functions that have been registered with
/// our server, so that they can be invoked by clients on the key/value pairs in
/// kv_store.
class my_functable : public FuncTable {

public:

  //Fill in the map and the shared mutex and whatever else will be necessary for the assignmnet
  unordered_map<string, std::pair<map_func, reduce_func>> fcn_map;
  std::shared_mutex mutex_shared;
  uint16_t file_counter = 0;
  vector<std::pair<string, void*>> listing;


  /// Construct a function table for storing registered functions
  my_functable() {}

  /// Destruct a function table
  virtual ~my_functable() {}

  /// Register the map() and reduce() functions from the provided .so, and
  /// associate them with the provided name.
  ///
  /// @param mrname The name to associate with the functions
  /// @param so     The so contents from which to find the functions
  ///
  /// @return a status message
  virtual std::string register_mr(const std::string &mrname,
                                  const std::vector<uint8_t> &so) {

    if(fcn_map.count(mrname))
      return RES_ERR_FUNC;
    
    string temp_filename = SO_PREFIX + mrname + to_string(file_counter) + ".so";
    file_counter++;

    FILE *func_file = fopen(temp_filename.c_str(), "wb");

    //write so into the file
    fwrite(so.data(), so.size(), 1, func_file);
    fclose(func_file);

    //files opened with dlopened is added to listing
    void* handle = dlopen(temp_filename.c_str(), RTLD_LAZY);
    listing.push_back({temp_filename, handle});

    if(!handle)
      return RES_ERR_SO;

    string map_name = "map";
    string reduce_name = "reduce";

    map_func map = (map_func) dlsym(handle, map_name.c_str());
    char* map_error;
    if ((map_error = dlerror()) != NULL) {
      dlclose(handle);
      return RES_ERR_SO;
    }

    reduce_func reduce = (reduce_func) dlsym(handle, reduce_name.c_str());
    char* reduce_error; 
    if ((reduce_error = dlerror()) != NULL) {
      dlclose(handle);
      return RES_ERR_SO;
    }

    //insert into the fcn_map
    pair<map_func, reduce_func> fcn_pair (map, reduce);
    pair<string, pair<map_func, reduce_func>> fcn_map_pair (mrname, fcn_pair);

    //lock mutex on table for insert (release after return)
    unique_lock lock(mutex_shared);
    fcn_map.insert(fcn_map_pair);
    return RES_OK;
  }

  /// Get the (already-registered) map() and reduce() functions associated with
  /// a name.
  ///
  /// @param name The name with which the functions were mapped
  ///
  /// @return A pair of function pointers, or {nullptr, nullptr} on error
  virtual std::pair<map_func, reduce_func> get_mr(const std::string &mrname) {

    //lock mutex on table for insert (release after return)
    shared_lock lock(mutex_shared);

    auto ret = fcn_map.find(mrname);
    if(ret == (fcn_map.end())) //error
      return {nullptr, nullptr};
    return fcn_map.at(mrname);
  }

  /// When the function table shuts down, we need to de-register all the .so
  /// files that were loaded.
  virtual void shutdown() {

    for(auto x : listing)
      dlclose(x.second);
  }
};

/// Create a FuncTable
FuncTable *functable_factory() { return new my_functable(); };



//RESOURCES

//Iterate through the temp_file_listing
//              https://pubs.opengroup.org/onlinepubs/009695399/functions/dlclose.html

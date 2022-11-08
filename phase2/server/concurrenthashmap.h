#include <cassert>
#include <functional>
#include <iostream>
#include <list>
#include <mutex>
#include <string>
#include <vector>

#include "map.h"

/// ConcurrentHashMap is a concurrent implementation of the Map interface (a
/// Key/Value store).  It is implemented as a vector of buckets, with one lock
/// per bucket.  Since the number of buckets is fixed, performance can suffer if
/// the thread count is high relative to the number of buckets.  Furthermore,
/// the asymptotic guarantees of this data structure are dependent on the
/// quality of the bucket implementation.  If a vector is used within the bucket
/// to store key/value pairs, then the guarantees will be poor if the key range
/// is large relative to the number of buckets.  If an unordered_map is used,
/// then the asymptotic guarantees should be strong.
///
/// The ConcurrentHashMap is templated on the Key and Value types.
///
/// This map uses std::hash to map keys to positions in the vector.  A
/// production map should use something better.
///
/// This map provides strong consistency guarantees: every operation uses
/// two-phase locking (2PL), and the lambda parameters to methods enable nesting
/// of 2PL operations across maps.
///
/// @param K The type of the keys in this map
/// @param V The type of the values in this map
template <typename K, typename V> class ConcurrentHashMap : public Map<K, V> {

  struct hash_bucket{
    std::vector<std::pair<K, V>> elements; 
    std::mutex bucketLock;
  };

public:
  int num_buckets;
  std::vector<hash_bucket> hashTable;

  /// Construct by specifying the number of buckets it should have
  ///
  /// @param _buckets The number of buckets
  ConcurrentHashMap(size_t _buckets) {
    num_buckets = _buckets;
    hashTable = std::vector<hash_bucket> (_buckets);
  }

  /// Destruct the ConcurrentHashMap
  virtual ~ConcurrentHashMap() {
    // std::cout << "ConcurrentHashMap::~ConcurrentHashMap() is not implemented";
    // clear();
  }

  /// Clear the map.  This operation needs to use 2pl
  virtual void clear() {
    // Growing phase, aquire locks
    for (int i = 0; i < num_buckets; i++) {
      (hashTable.at(i).bucketLock).lock();
      // Clear what is in the bucket
      for (int k = 0; k < num_buckets; i++) (hashTable.at(i).elements).pop_back();
    }

    // Shrinking phase, release locks
    for (int i = 0; i < num_buckets; i++) {
      (hashTable.at(i).bucketLock).unlock();
    }

  }

  /// Insert the provided key/value pair only if there is no mapping for the key
  /// yet.
  ///
  /// @param key        The key to insert
  /// @param val        The value to insert
  /// @param on_success Code to run if the insertion succeeds
  ///
  /// @return true if the key/value was inserted, false if the key already
  ///         existed in the table
  virtual bool insert(K key, V val, std::function<void()> on_success) {
    // Define the pair
    std::pair<K, V> thing;
    thing.first = key;
    thing.second = val;

    // Find the index
    // std::hash<K> keyHash = std::hash<K> key;
    std::hash<K> keyHash;
    size_t index = keyHash(key);
    index = index % num_buckets;

    (hashTable.at(index).bucketLock).lock();
    for (size_t i = 0; i < (hashTable.at(index).elements).size(); i++) {
      if (key == (hashTable.at(index).elements).at(i).first) {
        (hashTable.at(index).bucketLock).unlock();
        return false;
      }
    }
    (hashTable.at(index).elements).push_back(thing);
    (hashTable.at(index).bucketLock).unlock();
    on_success();
    return true;
  }

  /// Insert the provided key/value pair if there is no mapping for the key yet.
  /// If there is a key, then update the mapping by replacing the old value with
  /// the provided value
  ///
  /// @param key    The key to upsert
  /// @param val    The value to upsert
  /// @param on_ins Code to run if the upsert succeeds as an insert
  /// @param on_upd Code to run if the upsert succeeds as an update
  ///
  /// @return true if the key/value was inserted, false if the key already
  ///         existed in the table and was thus updated instead
  virtual bool upsert(K key, V val, std::function<void()> on_ins,
                      std::function<void()> on_upd) {
    // Check if you can insert the key/value pair
    if (insert(key, val, on_ins)){return true; } 

    // Find the index
    // std::hash<K> keyHash(key);
    std::hash<K> keyHash;
    size_t index = keyHash(key);
    index = index % num_buckets;

    // Check if the key already exists in the table
    (hashTable.at(index).bucketLock).lock();
    for (size_t i = 0; i < (hashTable.at(index).elements).size(); i++) {
      if (key == (hashTable.at(index).elements).at(i).first) {
        hashTable.at(index).elements.at(i).second = val;
        (hashTable.at(index).bucketLock).unlock();
        on_upd();
        return false;
      }
    }
    return false;
  }

  /// Apply a function to the value associated with a given key.  The function
  /// is allowed to modify the value.
  ///
  /// @param key The key whose value will be modified
  /// @param f   The function to apply to the key's value
  ///
  /// @return true if the key existed and the function was applied, false
  ///         otherwise
  virtual bool do_with(K key, std::function<void(V &)> f) {
    // Find the index
    std::hash<K> keyHash;
    size_t index = keyHash(key);
    index = index % num_buckets;

    (hashTable.at(index).bucketLock).lock();

    // Iterate over elements to find the matching key
    for (size_t i = 0; i < (hashTable.at(index).elements).size(); i++) {
      if (key == (hashTable.at(index).elements).at(i).first) { // Not sure if need result_t or something else

        // Apply the function passed into do_with to the val, with val's address to update val
        f((hashTable.at(index).elements.at(i).second)); // Continuing with the logic of succeded element in the if statement
        return true;
      }
    }
    (hashTable.at(index).bucketLock).unlock();
    return false;

  }

  /// Apply a function to the value associated with a given key.  The function
  /// is not allowed to modify the value.
  ///
  /// @param key The key whose value will be modified
  /// @param f   The function to apply to the key's value
  ///
  /// @return true if the key existed and the function was applied, false
  ///         otherwise
  virtual bool do_with_readonly(K key, std::function<void(const V &)> f) {
    // Find the index
    std::hash<K> keyHash;
    size_t index = keyHash(key);
    index = index % num_buckets;

    (hashTable.at(index).bucketLock).lock();

    // Iterate over elements to find the matching key
    for (size_t i = 0; i < (hashTable.at(index).elements).size(); i++) {
      if (key == (hashTable.at(index).elements).at(i).first) { // Not sure if need result_t or something else
        
        /* 
         * Apply the function passed into do_with to the val, with val's address
         * but f's parameter is a const V, meaning that val won't be changed 
         */
        f(hashTable.at(index).elements.at(i).second); // Continuing with the logic of succeded element in the if statement
        (hashTable.at(index).bucketLock).unlock();
        return true;
      }
    }
    (hashTable.at(index).bucketLock).unlock();
    return false;
  }

  /// Remove the mapping from a key to its value
  ///
  /// @param key        The key whose mapping should be removed
  /// @param on_success Code to run if the remove succeeds
  ///
  /// @return true if the key was found and the value unmapped, false otherwise
  virtual bool remove(K key, std::function<void()> on_success) {
    std::hash<K> keyHash;
    size_t index = keyHash(key);
    index = index % num_buckets;

    (hashTable.at(index).bucketLock).lock();
    std::pair<K, V> lastPair;

    // Iterate over elements to find matching key
    for (size_t i = 0; i < (hashTable.at(index).elements).size(); i++) {
      if (key == (hashTable.at(index).elements).at(i).first) {
        // Get the last pair
        lastPair = (hashTable.at(index).elements).back();
        // Replace the pair that's being removed with last pair
        hashTable.at(index).elements.pop_back();
        (hashTable.at(index).bucketLock).unlock();
        on_success();
        return true;
      }
    }
    (hashTable.at(index).bucketLock).unlock();
    return false;
  }

  /// Apply a function to every key/value pair in the map.  Note that the
  /// function is not allowed to modify keys or values.
  ///
  /// @param f    The function to apply to each key/value pair
  /// @param then A function to run when this is done, but before unlocking...
  ///             useful for 2pl
  virtual void do_all_readonly(std::function<void(const K, const V &)> f,
                               std::function<void()> then) {
   // Growing phase, aquire locks
    for (int i = 0; i < num_buckets; i++) {
      (hashTable.at(i).bucketLock).lock();
    }

    // Iterating through the entire hash table
    for (int index = 0; index < num_buckets; index++) {
      // Iterating through the elements in each bucket
      for (size_t i = 0; i < (hashTable.at(index).elements).size(); i++) {
        // Apply the function passed to f onto each KV pair
        f(hashTable.at(index).elements.at(i).first, hashTable.at(index).elements.at(i).second);
      }
    }
    // Call the passed then() function before unlocking
    then();
    // Shrinking phase, release locks
    for (int i = 0; i < num_buckets; i++) {
      (hashTable.at(i).bucketLock).unlock();
    }
  }
};

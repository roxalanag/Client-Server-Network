#include <deque>
#include <iostream>
#include <mutex>

#include "mru.h"

using namespace std;

/// my_mru maintains a listing of the K most recent elements that have been
/// given to it.  It can be used to produce a "top" listing of the most recently
/// accessed keys.
class my_mru : public mru_manager {

public:

  size_t max_elements;
  deque<string> mru_deque;
  mutex mru_lock;

  /// Construct the mru_manager by specifying how many things it should track
  ///
  /// @param elements The number of elements that can be tracked
  my_mru(size_t elements) :  max_elements(elements){}

  /// Destruct the mru_manager
  virtual ~my_mru() {}

  /// Insert an element into the mru_manager, making sure that (a) there are no
  /// duplicates, and (b) the manager holds no more than /max_size/ elements.
  ///
  /// @param elt The element to insert
  virtual void insert(const std::string &elt) {

    //finds and removes duplicates
    remove(elt); 

    //lock the mru
    lock_guard<mutex> lock(mru_lock); 

    //if theres no more space to insert element
    if(mru_deque.size() >= max_elements){
      mru_deque.pop_back(); //remove element from the back of the mru 
    }

    //add the new element to the front of the mru
    mru_deque.push_front(elt);

    //unlock the mru
    mru_lock.unlock();
  }


  /// Remove an instance of an element from the mru_manager.  This can leave the
  /// manager in a state where it has fewer than max_size elements in it.
  ///
  /// @param elt The element to remove
  virtual void remove(const std::string &elt) {

    //lock the mru
    lock_guard<mutex> lock(mru_lock); 

    //finds the element to remove and also removes duplicates
    for (size_t i = 0; i < mru_deque.size(); i++) {
      if (mru_deque.at(i).compare(elt) == 0){
        mru_deque.erase(mru_deque.begin() + i);
      }
    }

    //ulock the mru
    mru_lock.unlock();
    return;
  }


  /// Clear the mru_manager
  virtual void clear() { 
    lock_guard<mutex> lock(mru_lock); 
    mru_deque.clear();
  }

  /// Produce a concatenation of the top entries, in order of popularity
  ///
  /// @return A newline-separated list of values
  virtual std::string get() { 

    //lock the mru
    lock_guard<mutex> lock(mru_lock);
    string ret = "";

    //loop through the mru and append each element to return string
    for(auto it = mru_deque.begin(); it != mru_deque.end(); ++it){
    ret+= *it + "\n"; //add newline delimiter after each key
  }

    //unlock the mru
    mru_lock.unlock();

    return ret; 
  }
};


/// Construct the mru_manager by specifying how many things it should track
///
/// @param elements The number of elements that can be tracked in MRU fashion
///
/// @return An mru manager object
mru_manager *mru_factory(size_t elements) { 
  return new my_mru(elements); 
}
// http://www.cplusplus.com/reference/ctime/time/ is helpful here
#include <deque>
#include <iostream>
#include <memory>

#include "quota_tracker.h"

using namespace std;

/// quota_tracker stores time-ordered information about events.  It can count
/// events within a pre-set, fixed time threshold, to decide if a new event can
/// be allowed without violating a quota.
class my_quota_tracker : public quota_tracker {

public:

  struct event {
    time_t requestTime; 
    size_t resourceAmount;
  };

  deque<event> eventList; //for adding the deque for the quote tracking 
  size_t maxAmount; //maximum amount of service
  double quotaDuration; //keeps the iterator from reaching outside of desired items in the quota
  
  
  /// Construct a tracker that limits usage to quota_amount per quota_duration
  /// seconds
  ///
  /// @param amount   The maximum amount of service
  /// @param duration The time over which the service maximum can be spread out
  my_quota_tracker(size_t amount, double duration) 
  : maxAmount(amount), quotaDuration(duration) {}

  /// Destruct a quota tracker
  virtual ~my_quota_tracker() {}


  /// Decide if a new event is permitted, and if so, add it.  The attempt is
  /// allowed if it could be added to events, while ensuring that the sum of
  /// amounts for all events within the duration is less than q_amnt.
  ///
  /// @param amount The amount of the new request
  ///
  /// @return false if the amount could not be added without violating the
  ///         quota, true if the amount was added while preserving the quota
  virtual bool check_add(size_t amount) {
    time_t now; //create time stamp type
    time(&now); //get current time stamp
    size_t totalAmt = amount; 

    //set iterator to start of the deque and loop through until no more new data
    for(auto iter = eventList.begin(); iter < eventList.end(); iter++){
      
      if((*iter).requestTime > (now - quotaDuration)){
        totalAmt += (*iter).resourceAmount; //add to get total resource amount

        if(totalAmt > maxAmount) //violation because cannot exceed max resource amount
          return false; 

      } else break;
    }

    event evt; //make a new event to push back onto the deque
    evt.requestTime = time(NULL);
    evt.resourceAmount = amount;
    eventList.push_front(evt); //add to the deque

    return true; 
  }
};

/// Construct a tracker that limits usage to quota_amount per quota_duration
/// seconds
///
/// @param amount   The maximum amount of service
/// @param duration The time over which the service maximum can be spread out
quota_tracker *quota_factory(size_t amount, double duration) {
  return new my_quota_tracker(amount, duration);
}
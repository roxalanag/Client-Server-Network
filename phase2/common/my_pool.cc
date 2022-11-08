#include <atomic>
#include <condition_variable>
#include <functional>
#include <iostream>
#include <queue>
#include <thread>
#include <unistd.h>

#include "pool.h"

using namespace std;

class my_pool : public thread_pool {
public:
  //Conditino Variable used to wait and notify on proper conditions
  condition_variable cv;
  //Atomic allows for alerting the accept_client function on the termination of the program 
  atomic<bool> active_pool = true;
  //Vector containnig all of the threads 
  std::vector<std::thread> pool;
  //protection for the queue
  std::mutex queue_mutex;
  //Queue just holds ints that are the socket descriptors
  queue<int> work_queue;
  //Handlers defined for general processing and shutdown handling
  std::function<bool(int)> overall_handler;
  std::function<void()> shutdown_handle;

  /// construct a thread pool by providing a size and the function to run on
  /// each element that arrives in the queue
  ///
  /// @param size    The number of threads in the pool
  /// @param handler The code to run whenever something arrives in the pool
  my_pool(int size, function<bool(int)> handler) {
    overall_handler = handler;
    for(int i = 0; i < size; i++){
        pool.push_back(std::thread([this](){  //putting parameters into pool
          //This is the code that is the body of the thread
          int descriptor;
          while(check_active()){
            //Employ RAII with the queue mutex for waiting to check the necessary conditions 
            {
            unique_lock<mutex> lock(queue_mutex);

            cv.wait(lock, [this](){ return !work_queue.empty() || !check_active();});
            //upon BYE this statement will be reached since notify_all will be called and this function will allow the 
            //Thread to properly return
            if(!check_active()){
              break;
            }
            descriptor = work_queue.front();
            //remove work from the queue since its been obtained
            work_queue.pop();
            }

            // work_queue.push(handler);
            // cv.notify_one();
            //flag to indicate whether BYE was the operation which would return true 
            atomic<bool> continue_flag = true;

            continue_flag = overall_handler(descriptor);

            if(!continue_flag){
              close(descriptor);
            }
            else{
              //code to run upon BYE
              active_pool.store(false);
              //wait until all of the work_queue has emptied out
              while(work_queue.size() != 0){}
              
              shutdown_handle();
              
              if(descriptor!=0){
                close(descriptor);
              }
              //Statement is needed to notify all of the other threads to terminate
              cv.notify_all();
            }                
          }

        }));
      }
  }

  /// destruct a thread pool
  virtual ~my_pool() = default;

  /// Allow a user of the pool to provide some code to run when the pool decides
  /// it needs to shut down.
  ///
  /// @param func The code that should be run when the pool shuts down
  virtual void set_shutdown_handler(function<void()> func) {
    // cout << "my_pool::set_shutdown_handler() is not implemented";
    shutdown_handle = func;
  }

  /// Allow a user of the pool to see if the pool has been shut down
  virtual bool check_active() {
    // cout << "my_pool::check_active() is not implemented";
    // return false;
    return active_pool.load(); 

  }

  /// Shutting down the pool can take some time.  await_shutdown() lets a user
  /// of the pool wait until the threads are all done servicing clients.
  virtual void await_shutdown() {
    // cout << "my_pool::await_shutdown() is not implemented";
    //Join all existing threads
    for(int i=0;i<static_cast<int>(pool.size()); i++)
      {
        pool[i].join();
      }
  }

  /// When a new connection arrives at the server, it calls this to pass the
  /// connection to the pool for processing.
  ///
  /// @param sd The socket descriptor for the new connection
  virtual void service_connection(int sd) {
    // cout << "my_pool::service_connection() is not implemented";
    //Employ RAII with the queue mutex's lock
    {
      unique_lock<mutex> lock(queue_mutex);
      //Add the sd to put the work on the queue
      work_queue.push(sd);
    }

    cv.notify_all();
    }
};

/// Create a thread_pool object.
///
/// We use a factory pattern (with private constructor) to ensure that anyone
thread_pool *pool_factory(int size, function<bool(int)> handler) {
  return new my_pool(size, handler);
}

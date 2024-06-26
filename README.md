Mongoose Test 2668
========

Test utility to reproduce [cesenta/mongoose #2688](https://github.com/cesanta/mongoose/issues/2668)

# Requirements

  - You should install Homebrew

  - You should have XCode command line tools installed `xcode-select --install`
  
  - This was tested on an Intel based Mac running MacOS 14. 

# Setting up

  1. Clone MbedTLS

      ```
      git submodule init
      git submodule update
      ```

  2. Mosquitto must be installed on your Mac
  
     `brew install mosquitto`
    
  3. Copy Mosquitto conf files and keys
  
     `cp -v mosquitto-config/* "$(brew --prefix)"/etc/mosquitto`
    
  4. Start Mosquitto
  
      `brew services start mosquitto`
     
      **Warning** This will start a server listening on port 8833, any computer can connect to your Mac.  You can terminate the mosquitto server with the command `brew services stop mosquitto`.
     
  5. Build test program
  
      ```sh
      mkdir build
      cd build
      cmake ..
      make
      ```
    
  6. Run test program in 
  
      `sudo ./mongoose`
    
  7. When instructed, in another terminal window, configure the tun interface  
  
      `sudo ifconfig utun32 10.12.1.1 10.13.1.1`
    
  8. Go back to original terminal, Press Enter

  9. Press Enter again
  
  10. Test the configuration
  
        `ping -c 1 10.13.1.1`

  11. If ping works try the test message
  
        `./mqtt_req_resp`

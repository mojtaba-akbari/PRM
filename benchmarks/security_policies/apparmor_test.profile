# AppArmor profile to restrict /tmp writes
#include <tunables/global>

/usr/bin/python3 {
  #include <abstractions/base>
  #include <abstractions/python>
  
  # Allow normal operations
  /usr/bin/python3 mr,
  /usr/lib/python3*/** r,
  
  # Block /tmp writes for testing
  deny /tmp/** w,
  deny /tmp/** c,
}
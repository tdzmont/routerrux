# RouterRux

RouterRux is a proof of concept firmware flashing exploit kit.  It..

  - Uses CSRF to attempt urls to enable remote admin on routers (WRT54G)
  - Connects into admin gui from remote and fingerprints which router it is
  - Uploads an appropriate backdoored custom firmware 
 
Any vulnerabilities could be used on any routers which have them to help acess firmwarwe upload.   There are cases in which this can be acheived in one request without enabling remote administration.

This type of attack could work against theoretical internet of things devices if they have firmware upload capability.



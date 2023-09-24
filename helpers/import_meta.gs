// Import Metaxploit Lib
metaxploit = include_lib(current_path + "/metaxploit.so")
if not metaxploit then metaxploit = include_lib("/home/guest/Downloads/metaxploit.so")
if not metaxploit then metaxploit = include_lib("/lib/metaxploit.so")
if not metaxploit then metaxploit = include_lib(home_dir + "/metaxploit.so")
if not metaxploit then exit("Error: Can't find metaxploit library")
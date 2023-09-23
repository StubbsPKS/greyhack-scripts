//include<../helpers/author.gs>

//include<../helpers/colors.gs>

//Globals
////shell
globals.name = "dsh"
globals.date = "09/23/2023"
globals.coder = "dang3rMouse"
globals.version = 0.1
globals.running = true
globals.crypto = null
globals.objects = []

////db
globals.db = {}
globals.db.name = "payload"
globals.db.folder = null
globals.db.exploitFilesCount = 0
globals.db.passwordFilesCount = 0
globals.db.names = ["exploits", "passwords"]

//Local Vars
crypto = null
vfile = []

// Local variables for active user and active object.
local = {}
local.user = active_user
local.object = get_shell
local.computer = get_shell.host_computer
local.folder = get_shell.host_computer.File(current_path)
local.router = get_router
local.publicip = get_router.public_ip
local.localip = local.computer.local_ip

// Remote variables for active user and active object.
remote = {}
remote.user = active_user
remote.object = get_shell
remote.computer = get_shell.host_computer
remote.folder = get_shell.host_computer.File(current_path)
remote.router = get_router
remote.publicip = get_router.public_ip
remote.localip = remote.computer.local_ip

// Setup the current object
current = {}
current.user = remote.user
current.object = remote.object
current.computer = function
    if typeof(current.object) == "shell" then return current.object.host_computer
    if typeof(current.object) == "computer" then return current.object
    return null
end function
current.folder = current.computer.File(current_path)
current.router = remote.router
current.publicip = function
    return current.router.public_ip
end function
current.localip = current.computer.local_ip

// END VARS AND SETUP

// Set the crypto library if it is the local machine.
if remote.publicip == local.publicip and remote.localip == local.localip then
    // Get crypto from local system.
    crypto = include_lib("/lib/crypto.so")
    if not crypto then crypto = include_lib(parent_path(program_path) + "/crypto.so")
    if not crypto then
        print(globals.name + ": Cannot find 'crypto.so' library on system.")
        return false
    end if
end if

// Set the terminal to yours.
interface = get_custom_object
if interface.indexes.len != 2 then
    local = interface.local
    vfile = interface.vfile
    crypto = interface.crypto
end if

// Connect to the database server if there is one available.
if globals.libs.dbCheck then
    print("<color=yellow>Database Status:</color> <color=green>Available</color>")
else
    print("<color=yellow>Database Status:</color> <color=red>Not Available</color>")
end if

// Main Loop for a shell.
while globals.running
    input = user_input(colors.white + current.user + "@" + current.publicip + " [" + typeof(current.object) + "] # " + colors.clr, 0, 0)
    if input == "" then continue
    CommandExecute(input.trim.split(" "))
end while
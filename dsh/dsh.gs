//include<../helpers/author.gs>
//include<../helpers/disclaimer_snake.gs>

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

// Global library helper functions
globals.libs = {}

globals.libs["encrypt"] = function(string = "")
    if typeof(string) != "string" then return null
    // TODO: Add your own encryption.
    return string
end function

globals.libs["decrypt"] = function(string = "")
    if typeof(string) != "string" then return null
    // TODO: Add your own decryption.
    return string
end function

globals.libs["getPorts"] = function(ip)
    obj = {}
    obj.targetIP = null
    obj.router = null
    obj.ports = null

    targetIP = ip
    if not is_valid_ip(targetIP) then targetIP = nslookup(targetIP) // Check if domain 
    if not is_valid_ip(targetIP) then return null

    if is_lan_ip(targetIP) then
        obj.router = get_router
    else
        obj.router = get_router(targetIP)
    end if
    if not obj.router then return null

    if not is_lan_ip(targetIP) then
        obj.ports = obj.router.used_ports
    else
        obj.ports = obj.router.device_ports(targetIP)
    end if
    if typeof(obj.ports) == "string" then return null

    obj.targetIP = targetIP
    return obj
end function

globals.libs["scanLib"] = function(metalib, metaxploit)
    if not metalib then return null
    if not metaxploit then return null

    if globals.db.folder != null and globals.db.hasIndex("exploits") then
        obj = globals.libs.dbQueryExploits(metalib.lib_name, metalib.version)
        if obj != null then return obj
    end if

    obj = {}
    obj.name = metalib.lib_name
    obj.version = metalib.version
    obj.memorys = {}
    memorys = metaxploit.scan(metalib)
    for memory in memorys
        data = metaxploit.scan_address(metalib, memory).split("Unsafe check: ")
        if not data then continue
        obj.memorys[memory] = []
        for line in data
            if line == data[0] then continue
            if line == "" then continue
            value = line[line.indexOf("<b>")+3:line.indexOf("</b>")].replace(char(10), "")
            obj.memorys[memory].push(value)
        end for
    end for

    if globals.db.folder != null and globals.db.hasIndex("exploits") then
        if globals.libs.dbWriteExploits(obj) then
            print(colors.yellow + "Library '" + obj.name + "' version " + obj.version + " added." + colors.clr)
        else
            print(colors.orange + "Library '" + obj.name + "' version " + obj.version + " already exists." + colors.clr)
        end if
    end if

    return obj
end function

globals.libs["scanPort"] = function(metaxploit, targetIP, targetPort)
    if typeof(metaxploit) != "MetaxploitLib" then return null
    if not is_valid_ip(targetIP) then return null
    if typeof(targetPort) != "number" then return null

    netsession = metaxploit.net_use(targetIP, targetPort)
    if not netsession then
        print(globals.name + ": Failed to Connect")
        return null
    end if

    metalib = netsession.dump_lib
    if not metalib then
        print(globals.name + ": Failed to Dump Libs")
        return null
    end if

    return globals.libs.scanLib(metalib, metaxploit)
end function

globals.libs["dbCheck"] = function
    payload = local.computer.File(local.folder.path + "/" + globals.db.name)
    if not payload then return false
    globals.db.folder = payload

    for name in globals.db.names
        folder = local.computer.File(local.folder.path + "/" + globals.db.name + "/" + name)
        if not folder then return false
        globals.db[name] = folder
    end for

    return true
end function

globals.libs["dbCreate"] = function
    payload = local.computer.File(local.folder.path + "/" + globals.db.name)
    if not payload then
        print(colors.yellow + "Creating database folder '" + globals.db.name + "'..." + colors.clr)
        local.computer.touch(local.folder.path, globals.db.name)
        payload = local.computer.File(local.folder.path + "/" + globals.db.name)
        if not payload then
            print(color.red + "Folder '" + globals.db.name + "' already created" + colors.clr)
            return false
        else
            print(color.yellow + "Folder '" + globals.db.name + "' created" + colors.clr)
        end if
    end if
    globals.db.folder = payload

    for dbname in globals.db.names
        file = local.computer.File(local.folder.path + "/" + globals.db.name + "/" + dbname)
        if not file then
            print(colors.yellow + "Creating database folder '" + dbname + "'..." + colors.clr)
            local.computer.touch(local.folder.path + "/" + globals.db.name, dbname)
            file = local.computer.File(local.folder.path + "/" + globals.db.name + "/" + dbname)
            if not file then
                print(colors.red + "Folder '" + dbname + "' not created" + colors.clr)
                globals.db[dbname] = null
                return false
            else
                print(colors.yellow + "Folder '" + dbname + "' created" + colors.clr)
                globals.db[dbname] = file
            end if
        end if
    end for
    
    return true
end function

globals.libs["dbDeleteExploits"] = function(dbName = "")
    if dbName == "" then
        if globals.db.folder == null then return false
        globals.db.folder.delete
        globals.db.folder = null
        for dbname in globals.db.names
            globals.db[dbname] = null
        end for
    else
        if globals.db.hasIndex(dbName) == null then return false
        if typeof(globals.db[dbName]) != "file" then return false
        if globals.db[dbName] == null then return false
        globals.db[dbName].delete
        globals.db[dbName] = null
    end if
    return true
end function

globals.libs["dbParseExploits"] = function(result = "", filename = "")
    if typeof(result) != "string" then return null
    if typeof(filename) != "string" then return null
    if result.indexOf(";") == null then return null
    if result.indexOf(":") == null then return null

    exploits = result.split(";")[:-1]
    ret = {}
    ret.memorys = {}

    for exploit in exploits
        v = exploit.split(":")
        ret.name = v[0]
        ret.version = v[1]
        ret.memorys[v[2]] = []
    end for

    for exploit in exploits
        v = exploit.split(":")
        ret.memorys[v[2]].push(v[3])
    end for

    return ret
end function

globals.libs["dbParseToLines"] = function(result = "")
    if typeof(result) != "string" or result == "" then return null
    lines = result.split(";")[:-1]
    converted = []
    for line in lines
        converted.push(line)
    end for
    return converted
end function

globals.libs["dbStringifyExploits"] = function(result = {})
    if typeof(result) != "map" then return ""
    s = ""
    for memory in result.memorys
        for value in memory.value
            s = s + result.name + ":" + result.version + ":" + memory.key + ":" + value + ";"
        end for
    end for
    return s
end function

globals.libs["dbStringifyLines"] = function(result = [])
    if typeof(result) != "list" then return ""
    s = ""
    for line in result
        s = s + line + ";"
    end for
    return s
end function

globals.libs["dbWriteExploits"] = function(result = null)
    if typeof(result) != "map" then return null

    // Get current file for writing.
    name = "exploit" + str(globals.db.exploitFilesCount) + ".db"
    file = local.computer.File(globals.db.exploits.path + "/" + name)
    if not file then
        local.computer.touch(globals.db.exploits.path, name)
        file = local.computer.File(globals.db.exploits.path + "/" + name)
        if not file then false
    end if

    // Get content and check if in database.
    content = globals.libs.decrypt(file.get_content)
    stringify = globals.libs.dbStringifyExploits(result)

    if content.len + stringify.len <= 160000 then
        // Process lines
        lines = globals.libs.dbParseToLines(content)
        for line in lines
            v = line.split(":")
            if v[0] == result.name and v[1] == result.version then
                return false
            end if
        end for

        // Write content to database.
        content = content + stringify
        content = globals.libs.encrypt(content)
        result = file.set_content(content)
        if typeof(result) == "string" then return false
    else
        // Get current file for writing.
        globals.db.exploitFilesCount = globals.db.exploitFilesCount + 1
        name = "exploit" + str(globals.db.exploitFilesCount) + ".db"
        file = local.computer.File(globals.db.exploits.path + "/" + name)
        if not file then
            local.computer.touch(globals.db.exploits.path, name)
            file = local.computer.File(globals.db.exploits.path + "/" + name)
            if not file then false
        end if

        // Write content to database.
        content = content + stringify
        content = globals.libs.encrypt(content)
        result = file.set_content(content)
        if typeof(result) == "string" then return false
    end if

    return true
end function

globals.libs["dbQueryExploits"] = function(libname = "", libver = "", doprint = false)
    if globals.db.folder == null or not globals.db.hasIndex("exploits") then return null

    if libname == "" then
        retrieved = []
        for file in globals.db.exploits.get_files
            data = globals.libs.decrypt(file.get_content)
            lines = globals.libs.dbParseToLines(data)
            for line in lines
                v = line.split(":")
                if retrieved.indexOf(v[0]) == null then
                    retrieved.push(v[0])
                end if
            end for
        end for

        for name in retrieved
            print(name)
        end for
    else
        if libver == "" then
            retrieved = []
            for file in globals.db.exploits.get_files
                found = false
                data = globals.libs.decrypt(file.get_content)
                lines = globals.libs.dbParseToLines(data)
                for line in lines
                    v = line.split(":")
                    s = v[0] + ":" + v[1]
                    if v[0] == libname and retrieved.indexOf(s) == null then
                        retrieved.push(s)
                        found = true
                    end if
                end for
                if found then break
            end for

            for line in retrieved
                v = line.split(":")
                print(v[1])
            end for
        else
            converted = []
            for file in globals.db.exploits.get_files
                found = false
                data = globals.libs.decrypt(file.get_content)
                lines = globals.libs.dbParseToLines(data)
                for line in lines
                    v = line.split(":")
                    if v[0] == libname and v[1] == libver then
                        converted.push(line)
                        found = true
                    end if
                end for
                if found then break
            end for

            if doprint then
                for line in converted
                    v = line.split(":")
                    print("  --> " + v[2] + " [" + v[3] + "]")
                end for
            else
                stringify = globals.libs.dbStringifyLines(converted)
                return globals.libs.dbParseExploits(stringify)
            end if
        end if
    end if
    return null
end function

// END VARS AND SETUP



// Set the terminal to yours.
interface = get_custom_object
if interface.indexes.len != 2 then
    local = interface.local
    vfile = interface.vfile
    crypto = interface.crypto
end if

// ------------------- Shell Commands --------------------

globals.commandsShell = {}

globals.commandsShell["scp"] = { "name": "scp", "desc": "Upload or download from remote system.", "args": "[path | [-d path] | [-u path]]" }
globals.commandsShell["scp"]["run"] = function(argv = [])
    if typeof(argv) != "list" then return print(globals.name + ": Invalid argument vector given.")
    if argv.len != 2 and argv.len != 3 then return print(globals.name + ": Does NOT take any arguments.")

    if argv.len == 2 then
        if argv[1].indexOf("/") == 0 then
            result = local.object.scp(argv[1], current.folder.path, current.object)
            if typeof(result) == "string" then return print(globals.name + ": " + result)
        else
            result = local.object.scp(local.folder.path + "/" + argv[1], current.folder.path, current.object)
            if typeof(result) == "string" then return print(globals.name + ": " + result)
        end if
    else
        if argv[1] == "-d" then
            if argv[2].indexOf("/") == 0 then
                result = current.object.scp(argv[2], local.folder.path, local.object)
                if typeof(result) == "string" then return print(globals.name + ": " + result)
            else
                result = current.object.scp(current.folder.path + "/" + argv[2], local.folder.path, local.object)
                if typeof(result) == "string" then return print(globals.name + ": " + result)
            end if
        else if argv[1] == "-u" then
            if argv[2].indexOf("/") == 0 then
                result = local.object.scp(argv[2], current.folder.path, current.object)
                if typeof(result) == "string" then return print(globals.name + ": " + result)
            else
                result = local.object.scp(local.folder.path + "/" + argv[2], current.folder.path, current.object)
                if typeof(result) == "string" then return print(globals.name + ": " + result)
            end if
        end if
    end if
    return true
end function

// ----------------- Computer Commands -------------------

globals.commandsComputer = {}

globals.commandsComputer["ps"] = { "name": "ps", "desc": "Display process information.", "args": "" }
globals.commandsComputer["ps"]["run"] = function(argv = [])
    if typeof(argv) != "list" then return print(globals.name + ": Invalid argument vector given.")
    if argv.len != 1 then return print(globals.name + ": Takes no arguments.")

    info = "USER PID COMMAND"
    procs = current.computer.show_procs
    for proc in procs.split(char(10))[1:]
        usr = proc.split(" ")[0]
        pid = proc.split(" ")[1]
        cmd = proc.split(" ")[4]
        info = info + char(10) + usr + " " + pid + " " + cmd
    end for
    print(format_columns(info))
    return true
end function

// ------------------ General Commands -------------------

globals.commands = {}

globals.commands["help"] = { "name": "help", "desc": "Display a list of commands.", "args": "" }
globals.commands["help"]["run"] = function(argv = [])
    if typeof(argv) != "list" then return print(globals.name + ": Invalid argument vector given.")
    if argv.len != 1 then return print(globals.name + ": Does NOT take any arguments.")

    info = typeof(current.object) + " commands:" + "\n"
    for command in globals.commands
        info = info + char(9) + colors.term + command.value.name + colors.clr + " " + command.value.desc + "\n"
    end for

    if typeof(current.object) == "shell" or typeof(current.object) == "computer" then
        for command in globals.commandsComputer
            info = info + char(9) + colors.orange + command.value.name + colors.clr + " " + command.value.desc + "\n"
        end for
        if typeof(current.object) == "shell" then
            for command in globals.commandsShell
                info = info + char(9) + colors.white + command.value.name + colors.clr + " " + command.value.desc + "\n"
            end for
        end if
    end if

    print(info)
    return true
end function

globals.commands["scan"] = { "name": "scan", "desc": "Port Scanner", "args": "[IP] [PORT]"}
globals.commands["scan"]["run"] = function(argv = [])
    if typeof(argv) != "list" then return print(globals.name + ": Invalid arg")
    if argv.len < 2 or argv.len > 3 then return print(globals.name + ": Wrong number of args")

    if argv.len == 2 then
        obj = globals.libs.getPorts(argv[1])
        if not obj then return print(globals.name + ": Address Not Found")
        if obj.ports.len == 0 then return print(globals.name + ": Scan Returned No Ports")

        info = "# PORT STATE SERVICE VERSION LAN"
        count = 0
        for port in obj.ports
            serverInfo = obj.router.port_info(port)
            status = colors.green + "Open" + colors.clr

            if not is_lan_ip(obj.targetIP) and port.is_closed then
                status = colors.red + "Closed" + colors.clr
            end if
            info = info + char(10) + count + " " +  port.port_number + " " + status + " " + serverInfo + " " + port.get_lan_ip
            count = count + 1
        end for
        print(format_columns(info))
        choice = user_input("Which Port? ").to_int
        if choice < 0 then return print("Invalid choice " + choice)
        if choice > (obj.ports.len -1) then return print("Invalid choice " + choice)

        // Import Metaxploit Lib
        metaxploit = include_lib(current_path + "/metaxploit.so")
        if not metaxploit then metaxploit = include_lib("/home/guest/Downloads/metaxploit.so")
        if not metaxploit then metaxploit = include_lib("/lib/metaxploit.so")
        if not metaxploit then metaxploit = include_lib(home_dir + "/metaxploit.so")
        if not metaxploit then exit("Error: Can't find metaxploit library")

        //Let's get scanning!
        print("Scanning: " + obj.targetIP + ":" + obj.ports[choice].port_number)
        globals.libs.scanPort(metaxploit, obj.targetIP, obj.ports[choice].port_number)
    else if argv.len == 3 then
        // Import Metaxploit Lib
        metaxploit = include_lib(current_path + "/metaxploit.so")
        if not metaxploit then metaxploit = include_lib("/home/guest/Downloads/metaxploit.so")
        if not metaxploit then metaxploit = include_lib("/lib/metaxploit.so")
        if not metaxploit then metaxploit = include_lib(home_dir + "/metaxploit.so")
        if not metaxploit then exit("Error: Can't find metaxploit library")
        // We have a port, let's do some scanning
        targetPort = argv[2].to_int
        if typeof(targetPort) == "number" then
            targetIP = argv[1]
            if not is_valid_ip(targetIP) then targetIP = nslookup(targetIP) // Check if domain
            if not is_valid_ip(targetIP) then 
                print(globals.name + ": IP Not Found - " + targetIP)
                return false
            end if
            // The IP is valid
            globals.libs.scanPort(metaxploit, targetIP, targetPort)
        else
            print(globals.name + ": Port was NaN - " + targetPort)
            return false
        end if
    else
        print(globals.name + ": Wrong number of args")
    end if
    return true
end function

globals.commands["dbquery"] = { "name": "dbquery", "desc": "Query the database.", "args": "[dbname] [(opt) [libname] or [hash]] [(opt) libver]" }
globals.commands["dbquery"]["run"] = function(argv = [])
    if typeof(argv) != "list" then return print(globals.name + ": Invalid argument vector given.")
    if argv.len > 4 then return print(globals.name + ": Takes two arguments one is optional.")
    if not globals.db.hasIndex("exploits") or (globals.db.hasIndex("exploits") and globals.db.exploits == null) then return print(globals.name + ": Not connected to database.")

    if argv.len == 4 then
        if argv[1] == "exploits" then
            globals.libs.dbQueryExploits(argv[2], argv[3], true)
        else
            print(globals.name + ": <color=orange>Database entry does NOT exist.</color>")
        end if
    else if argv.len == 3 then
        if argv[1] == "passwords" then
            m = globals.libs.dbQueryPasswords(argv[2])
            if typeof(m) == "map" then
                print("<color=white>Password: " + m.pass + "</color>")
            else
                print(globals.name + ": <color=orange>Cannot lookup hash maybe improperly formatted.</color>")
            end if
        else if argv[1] == "exploits" then
            globals.libs.dbQueryExploits(argv[2], "")
        else
            print(globals.name + ": <color=orange>Database entry does NOT exist.</color>")
        end if
    else if argv.len == 2 then
        if argv[1] == "passwords" then
            globals.libs.dbQueryPasswords("")
        else if argv[1] == "exploits" then
            globals.libs.dbQueryExploits("", "")
        else
            print(globals.name + ": <color=orange>Database entry does NOT exist.</color>")
        end if
    else
        print("Databases Available:")
        for dbname in globals.db.names
            print("  " + dbname)
        end for
        print(globals.name + ": <color=white>You must atleast specify a database name.</color>")
    end if
    return true
end function

globals.commands["dbcreate"] = { "name": "dbcreate", "desc": "Create a database.", "args": "" }
globals.commands["dbcreate"]["run"] = function(argv = [])
    if typeof(argv) != "list" then return print(globals.name + ": Invalid argument vector given.")
    if argv.len != 1 then return print(globals.name + ": Takes no arguments.")
    if globals.libs.dbCheck then
        print("<color=red>Database already exists.")
        return true
    end if
    return globals.libs.dbCreate
end function

globals.commands["dbdelete"] = { "name": "dbdelete", "desc": "Delete an entry from the database.", "args": "[(opt) foldername]" }
globals.commands["dbdelete"]["run"] = function(argv = [])
    if typeof(argv) != "list" then return print(globals.name + ": Invalid argument vector given.")
    if argv.len > 2 then return print(globals.name + ": Takes one optional argument.")
    if not globals.db.hasIndex("exploits") or (globals.db.hasIndex("exploits") and globals.db.exploits == null) then return print(globals.name + ": Not connected to database.")

    if argv.len == 2 then
        if globals.libs.dbDeleteExploits(argv[1]) then
            print("<color=yellow>Database deleted.</color>")
        else
            print("<color=orange>Database failed to delete.</color>")
        end if
    else
        if globals.libs.dbDeleteExploits then
            print("<color=yellow>Database deleted.</color>")
        else
            print("<color=orange>Database failed to delete.</color>")
        end if
    end if
    return true
end function

// ----------------- Main Program --------------------

if params.len != 0 then exit("Usage: " + program_path.split("/")[-1])

// Execute given command with arguments.
CommandExecute = function(argv = [])
    if typeof(argv) != "list" then return print(globals.name + ": Invalid type, needs to be of type 'string'.")
    //if argv.len > 1 and argv[1] == "" then return print(globals.name + ": No arguments given when expected.")

    commands = globals.commands
    if typeof(current.object) == "shell" or typeof(current.object) == "computer" then
        commands = commands + globals.commandsComputer
        if typeof(current.object) == "shell" then
            commands = commands + globals.commandsShell
        end if
    end if

    if not commands.hasIndex(argv[0].lower.trim) then return print(globals.name + ": Command not found!")
    command = commands[argv[0].lower.trim]
    if argv.len > 1 then
        if argv[1] == "-h" or argv[1] == "--help" then
            return print("Usage: " + command.name + " " + command.args)
        end if
    end if

    return command.run(argv)
end function

// Splash screen for my shell.
splash = "=============================" + char(10)
splash = splash + "       Version " + globals.version + char(10)
splash = splash + "      Coded by " + globals.coder + char(10)
splash = splash + "     Based on SH by 5n4k3"
splash = "=============================" + char(10)
print(splash)

// Connect to the database server if there is one available.
if globals.libs.dbCheck then
    print(colors.term + "Database Status: " + colors.green + "AVAILABLE" + colors.clr)
else
    print(colors.term + "Database Status: " + colors.red + "NOT AVAILABLE" + colors.clr)
end if

// Main Loop for a shell.
while globals.running
    // Based on the current.user, we will change username color on the terminal
    if current.user == "root" then 
        // On my term IRL this would be red to warn me that I'm root, but root is good in this game, so green!
        termUser = colors.green + current.user + colors.clr
    else if current.user == "guest" then
        // Guest is the worst, so it gets red
        termUser = colors.red + current.user + colors.clr
    else
        // Regular user, they can escalate so yellow seems good?
        termUser = colors.yellow + current.user + colors.clr
    end if

    // Let's put the string together for the terminal text
    termString=colors.term + termUser + "@" + current.publicip + " [" + typeof(current.object) + "] # " + colors.clr 
    
    input = user_input(termString, 0, 0)
    if input == "" then continue
    CommandExecute(input.trim.split(" "))
end while
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
local mssql = require "mssql"
local nmap = require "nmap"
local smb = require "smb"
local stdnse = require "stdnse"
local io = require "io"

description= [[ Description ]]

author = {"mrdenchik"}

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}

hostrule = function(host)
 if( mssql.Helper.WasDiscoveryPerformed(host) ) then
  return mssql.Helper.GetDiscoveredInstances(host) ~= nil
 else
  local sqlDefaultPort = nmap.get_port_state(host, {number = 1433, protocol = "tcp"})
  local sqlBrowserPort = nmap.get_port_state(host, {number = 1434, protocol = "udp"})
  local smbPortNumber = smb.get_port(host)
   if(
      (sqlBrowserPort and (sqlBrowserPort.state == "open" or sqlBrowserPort.state == "open|filtered")) or
      (sqlDefaultPort and (sqlDefaultPort.state == "open" or sqlDefaultPort.state == "open|filtered")) or
      (smbPortNumber ~= nil)
     ) then
    return true
   else
    print("Error ...")
   end 
 end
end

action = function(host, port)

  local scriptOutput = stdnse.output_table()
  local path = stdnse.get_script_args("path")
  local dns = stdnse.get_script_args("dns")
  
  local status, instanceList = mssql.Helper.GetTargetInstances(host)
  if(not status) then
   if(not mssql.Helper.WasDiscoveryPerformed(host)) then
    mssql.Helper.Discover(host)
   end
   instanceList = mssql.Helper.GetDiscoveredInstances(host)
  else
   print("status=false")
  end

  if(not instanceList) then
   local output = stdnse.output_table()
   output.hostname = host.name
   return stdnse.format_output(false, output)
   -- return stdnse.format_output(false, instanceList or "")
  else
   file = io.open(path, "a+")
   for _, instance in ipairs(instanceList) do

     local iName = instance.instanceName;
     if(iName == nil) then
      iName = "nil"
     end
     hName = host.name

     if(host.name == nil or host.name == "") then      
      -- для ip из других сетей получим FQDN
      --local command = "nslookup "..host.ip.." "..dns.." | awk -F= '{printf $2}' | sed 's/.$//' | sed 's/ //'"
      local command = "nslookup -query=ptr "..host.ip.." "..dns.." | awk -F= '{printf $2}' | sed 's/.$//' | sed '/^$/d' |sed 's/ //'"
      hName = fbash(command)     
       --если ptr записи нет - не пишем в файл
      if(hName ~= "") then
       file:write(hName.."|"..host.ip.."|"..iName.."\n")
      end
     else
      file:write(hName.."|"..host.ip.."|"..iName.."\n")
     end
   end
   file:flush()
   file:close()
  end

  return scriptOutput
end

fbash = function(command)
 local handle = io.popen(command)
 local result = handle:read("*a")
 handle:close()
 return result
end

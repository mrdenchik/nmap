local mssql = require "mssql"
local nmap = require "nmap"
local smb = require "smb"
local stdnse = require "stdnse"
local io = require "io"
local os = require "os"

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
  local path_CMS = stdnse.get_script_args("path_CMS")
  local path_1C = stdnse.get_script_args("path_1C")
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
   --файл данных для MS SQL CMS
   local file_CMS = io.open(path_CMS, "a+")
   --фал данных для регистра сведений 1С
   local file_1C = io.open(path_1C, "a+")
   for _, instance in ipairs(instanceList) do

     local iName = instance.instanceName
     local iName_CMS, iName_1C
     
     if(iName == nil or iName == "MSSQLSERVER") then
      iName_CMS = ""
     else
      iName_CMS = "\\\\"..iName
     end
    
     iName_1C = iName
     if(iName == nil) then
      iName_1C = "MSSQLSERVER"
     end

     hName = host.name

     local nPort = instance.port
     if(nPort == nil or nPort.number == nil ) then
      port = "1433"
     else
      port = nPort.number
     end

     if(host.name == nil or host.name == "") then      
      -- для ip из других сетей получим FQDN
      local command = "nslookup -query=ptr "..host.ip.." "..dns.." | awk -F= '{printf $2}' | sed 's/.$//' | sed '/^$/d' |sed 's/ //'"
      hName = f_ExecuteBash(command)     
       --если ptr записи нет - не пишем в файл
      if(hName ~= "") then
       file_1C:write(f_GetCurrentDateTime().."|"..string.upper(hName).."|"..host.ip.."|"..iName_1C.."|true".."\n")
       file_CMS:write(string.upper(hName)..iName_CMS..","..port.."\n") -- "," это разделитель порта в sqlcmd
      end
     else
      file_1C:write(f_GetCurrentDateTime().."|"..string.upper(hName).."|"..host.ip.."|"..iName_1C.."|true".."\n")
      file_CMS:write(string.upper(hName)..iName_CMS..","..port.."\n") -- "," это разделитель порта в sqlcmd
     end
   end
   file_1C:flush()
   file_1C:close()
   file_CMS:flush()
   file_CMS:close()
  end

  return scriptOutput
end

f_ExecuteBash = function(command)
 local handle = io.popen(command)
 local result = handle:read("*a")
 handle:close()
 return result
end

f_GetCurrentDateTime = function()
 return os.date("%Y-%m-%d %H:%M:%S", os.time())
end

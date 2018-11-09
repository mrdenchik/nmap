local mssql = require "mssql"
local nmap = require "nmap"
local smb = require "smb"
local stdnse = require "stdnse"

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
   file = io.open("/home/sadmin/mssql.txt", "a+")
   for _, instance in ipairs(instanceList) do
     print(instance:GetName())
     file:write(instance:GetName().."\n")
   end
   file:flush()
   file:close()
  end

  return scriptOutput
end

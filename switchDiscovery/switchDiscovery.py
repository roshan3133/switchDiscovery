#!/usr/bin/env python

###########################################
#Author : Aniket Gole
# This Script will discover Cisco switch information from IP or Subnet address.
# It needs atlease one ip address/subnet, username, password at execution time. 
############################################
import commands
import paramiko
from netaddr import *
import getpass
import sys
import socket
import argparse
from logger import log as logger

# Make ssh connection on any ssh based remote device.
def ssh_conn(ip, user, passwd, cmd):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip , username=user, password=passwd)
    stdin, stdout, stderr = ssh.exec_command(cmd)
    a = stdout.readlines()
    b = stderr.readlines()
    return a, b

# Command Execution
def cmd_exe(cmd, shh):
    stdin, stdout, stderr = ssh.exec_command(cmd, get_pty=True)
    out = stdout.read()
    err = stderr.read()
    return out, err

# Checking PinPong from execution server to Destination any switch
def ping_test(ip):
    reply = commands.getstatusoutput('ping -c 1 ' + ip)
    if reply[0] == 0:
      return True
    else:
      return False

#Get the list of ips available in given subnet
def ips_in_subnet(subnet):
    ip_list = []
    ips = IPNetwork(subnet)
    for ip in ips:
      ip_list.append(ip)
    return ip_list

# Check ssh port connectivity from execution server to destination switch
def check_ssh(ip, port=22):
    try:
      client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      client_socket.settimeout(5)
      result = client_socket.connect_ex((ip, port))
      if result == 0:
        return True
      else:
	return False
    except socket.error as e:
      return False

# Execute cammand to get output on any switch
def get_switch_info(sub, ip, user, passwd, cmd):
    out = []
    out.append(sub)
    out.append(ip)
    #sys.exit(0)
    # checking ping first
    ping_out = ping_test(ip)
    if ping_out == True:
      out.append("Pinging")
      # check ssh
      ssh_test = check_ssh(ip)
      if ssh_test == True:
        out.append("ShhWorks")
        # create ssh connection
        try:
          output, err = ssh_conn(ip, user, passwd, cmd)
          #output, err = cmd_exe(cmd, ssh)
          #print "output", output
          #print "err", err
          out.append("RightPass")
          if err:
            out.append(err)
            #print ("Device % getting error %" % (ip,err))
	    return False
          else:
            #print out
            #out.append(output)
	    for val in output:
    		if "Processor" in val:
      		  out.append(val.split(" ")[-1].strip())
    		elif "Device" in val :
      		  out.append(val.split(" ")[-1].strip())
    		elif "cisco Nexus" in val:
      		  out.append("Cisco")
      		  out.append(val.split(" ")[3])
    		elif "NXOS:" in val :
      		  out.append(val.strip())
            logger.info(out)
            return out
        # execute cmd
        except Exception, e:
          logger.error( str(e))
 	  logger.error( "wrong password for switch %s" % (ip))
          out.append("WrongPass")
          logger.info(out)
 	  return out
      else:
        out.append("NoShh")
	logger.error("Device %s not connecting on ssh port" % (ip))
	return False
    else:
      logger.error("Device %s not pingging" % (ip))
      out.append("NoPing")
      return False 

def ipv4_validation(ip):
  try:
    stat = IPAddress(ip)
    return True
  except:
    return False

def ipv4_subnet_validation(subnet):
  try:
    stat = IPNetwork(subnet)
    return True
  except:
    return False

if __name__ == "__main__":
  parser = argparse.ArgumentParser()
  parser.add_argument("-ip", "--Ipaddress", nargs='*',type=str, default=None, help="Prvide IP address in sapce separeded format only if multiple. OR")
  parser.add_argument("-ipf", "--IpaddressFile", type=file, help="Provilde filename with path with list of ip address separated with new line")
  parser.add_argument("-sub", "--Subnet", nargs='*',type=str, default=None, help="Prvide subnet in sapce separeded format only if multiple. OR ")
  parser.add_argument("-subf", "--SubnetFile", type=file, help="Provilde filename with path with list of subnet separated with new line")
  parser.add_argument("-user", "--Username", nargs='*', type=str, default=None, help="Provide switch Username for login.")
  args = parser.parse_args()
  if args.IpaddressFile or args.Ipaddress and args.Username:
    if args.IpaddressFile and args.Username:
      ips = [line.rstrip('\n') for line in args.IpaddressFile]
      for ip in ips:
        s = ipv4_validation(ip)
        if s == False:
          print "This ip %s is not valid ip address" % ip 
          logger.error("This ip %s is not valid ip address" % ip )
          sys.exit(0)
    elif args.Ipaddress != None and args.Username:
      ips = args.Ipaddress
      print ips
      for ip in ips:
        s = ipv4_validation(ip)
        if s == False:
          print "This ip %s is not valid ip address" % ip 
          logger.error( "This ip %s is not valid ip address" % ip )
          sys.exit(0)
  elif args.SubnetFile or args.Subnet and args.Username:
    if args.SubnetFile and args.Username:
      subnets = [line.rstrip('\n') for line in args.SubnetFile]
      print subnets
      for subnet in subnets:
        s = ipv4_subnet_validation(subnet)
        if s == False:
          print "This subnet %s is not valid subnet" % subnet 
          logger.error( "This subnet %s is not valid subnet" % subnet )
          sys.exit(0)
    elif args.Subnet and args.Username:
      subnets = [line.rstrip('\n') for line in args.Subnet]
      print subnets
      for subnet in subnets:
        s = ipv4_subnet_validation(subnet)
        if s == False:
          print "This subnet %s is not valid subnet" % subnet 
          logger.error( "This subnet %s is not valid subnet" % subnet )
          sys.exit(1)
  else:
    parser.print_help()
    sys.exit(1)

  user = args.Username[0]
  print user
  passwd = getpass.getpass()
  fout = open("output", "a")
  if args.Subnet or args.SubnetFile:
    for sub in subnets:
      sub = sub.strip()
      ips = ips_in_subnet(sub)
      for ip in ips:
        out = get_switch_info(sub, str(ip), user, passwd, "sh ver")
        print out
        fout.write(str(out))
        fout.write("\n")
  elif args.Ipaddress or args.IpaddressFile:
    sub = "SubNotGiven"
    for ip in ips:
        out = get_switch_info(sub, str(ip), user, passwd, "sh ver")
        print out
        fout.write(str(out))
        fout.write("\n")
    
  fout.close()
  print "Script Execution Completed."

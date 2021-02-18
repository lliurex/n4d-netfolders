#!/usr/bin/python3
import os
import os.path
import shutil
import json
import re
import subprocess
import stat
import grp
import pwd
import imp
import threading
import n4d.responses
import n4d.server.core
sambaparser=imp.load_source("SambaParser","/usr/share/n4d/python-plugins/support/sambaparser.py")


class NetFoldersManager:

	#ERRORS CODE
	# restore_acls=-10
	
	
	LOCAL_CONF_FOLDER="/var/lib/lliurex-folders/local/"
	SMB_CONF_FOLDER="/var/lib/lliurex-folders/smb/"
	BASE_DIR="/net/server-sync/"
	
	def __init__(self):
			
		self.debug=False
		
		self.core=n4d.server.core.Core.get_core()
		
		self.acl_thread=threading.Thread()
		
		if not os.path.exists(self.LOCAL_CONF_FOLDER):
			os.makedirs(self.LOCAL_CONF_FOLDER)
		if not os.path.exists(self.SMB_CONF_FOLDER):
			os.makedirs(self.SMB_CONF_FOLDER)
		
	#def __init__
	
	
	def startup(self,options):
		
		self.check_local_folders()
		self.get_shared_folders()
		
	#def startup
	
	def backup(self,backup_target=None,backup_dest="/backup"):
		if not backup_dest.endswith("/"):
			backup_dest+="/"
		file_path=backup_dest+get_backup_name("NetFoldersManager")
		if backup_target is None:
			backup_target = [os.path.join(self.BASE_DIR,x) for x in os.listdir(self.BASE_DIR)]
		#Old n4d: return objects['FileUtils'].backup(backup_target,file_path)
		n4d.responses.build_successful_call_response(objects['FileUtils'].backup(backup_target,file_path))

	#def backup

	def restore(self,backup_file=None):
		if backup_file==None:
			for f in sorted(os.listdir("/backup"),reverse=True):
				if "NetFoldersManager" in f:
					backup_file="/backup/"+f
					break
		#Old n4d: return objects['FileUtils'].restore(backup_file,'/')
		n4d.responses.build_successful_call_response(objects['FileUtils'].restore(backup_file,'/'))

	#def restore

	def mount_gluster_volumes(self):
		try:
			list_mount = []
			if not os.path.exists('/var/lib/n4d-glusterfs/volumes'):
				#Old n4d: return True
				n4d.responses.build_successful_call_response(True)
			f = open('/var/lib/n4d-glusterfs/volumes')
			lines = f.readlines()
			to_mount = [ x[:x.find('#') - 1] for x in lines ]
			for x in range(1,10):
				mounted=objects['MountManager'].mount_list().keys()
				to_mount_b=[]
				for item in to_mount:
					#to_mount_b.append(" ".join(item.split(" ")[0]))
					to_mount_b.append(item.split(" ")[0])
				to_process=[]
				for item in to_mount_b:
					if item not in mounted:
						to_process.append(item)
				if len(to_process)==0:
					break
				for item in to_mount:
					for item2 in to_process:
						if item.find(item2)!=-1:
							os.system("mount -t glusterfs -o acl " + item )
							continue
		except Exception as e:
			print(e)
			
		#Old n4d: return True
		return n4d.responses.build_successful_call_response(True)

	#def mount_gluster_volumes


	def get_acl_info(self,path):
		
		info={}
		regex="(\w+:|\A)(user|group|mask|other):([a-zA-Z0-9\-]*):([r|w|x|\-]{1,3})\s*[#]*(\S+)*\Z"
		os.environ["LANG"]="C"
		p=subprocess.Popen(["getfacl","-n",path],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
		out=p.communicate()[0]
		out=out.decode("utf-8")
		
		info["acl"]=[]
		tmp=oct(stat.S_IMODE(os.lstat(path).st_mode)).lstrip("0o")
		info["perm"]=tmp
		
		
		info["path"]=path
		
		for item in out.split("\n"):
			
			#item=item.strip("\n")
			x=re.match(regex,item)
			
			if x!=None:
				
				special=x.group(1)
				type_=x.group(2)
				custom_group=x.group(3)
				acl=x.group(4)
				extra=x.group(5)
				
				if special.find("default")!=-1:
					mode="-d -m"
				else:
					mode="-m"
					
				if type_=="group":
					type_="g:"
				elif type_=="user":
					type_="u:"
				elif type_=="mask":
					type_="m:"
				elif type_=="other":
					type_="o:"
					
				
				info["acl"].append([mode,type_+custom_group+":"+acl])
					

		#Old n4d: return info
		return n4d.responses.build_successful_call_response(info)
		
	#def get_acl_info
	
	def get_missing_acl_conf(self,info):
		
		ret=[]
		ret_={}
		for f in os.listdir(NetFoldersManager.LOCAL_CONF_FOLDER):
			try:
				ff=open(NetFoldersManager.LOCAL_CONF_FOLDER+f)
				txt="".join(ff.readlines())
				ff.close()
				orig_info=eval(txt)

				for item in orig_info:
					found=False
					if orig_info[item]["path"]==info["path"]:

						for acl in orig_info[item]["acl"]:
							if not acl in info["acl"]:
								ret.append(acl)
							found=True
							
						if found:
						
							ret_[info["path"]]={}
							ret_[info["path"]]["path"]=info["path"]
							ret_[info["path"]]["perm"]=orig_info[item]["perm"]
							ret_[info["path"]]["acl"]=ret
								
							#Old n4d: return(ret_)
							return n4d.responses.build_successful_call_response(ret_)
			
				
			except Exception as e:
				print (e)
			
			
		#Old n4d: return None
		return n4d.responses.build_successful_call_response(None)
			
		
	#def get_diferences
	
	def parse_local_folders_conf(self):
		
		for f in sorted(os.listdir(self.LOCAL_CONF_FOLDER)):
			try:
				#execfile(self.LOCAL_CONF_FOLDER+f)
				#self.local_dirs=dict(self.local_dirs.items()+locals()["folder"].items())
				
				f_=open(self.LOCAL_CONF_FOLDER+f,"r")
				data=json.load(f_)
				f_.close()				
				#self.local_dirs=dict(self.local_dirs.items()+data.items())
				self.local_dirs.update(data)
				
			except Exception as e:
				print("!!",e,"File: " + f)



	
	def check_local_folders(self,recursive=False):

		# this is no longer true. root access had to be enabled after all
		'''
		if os.path.exists("/lib/systemd/system/net-server\\x2dsync.mount"):
			# Root has no access to /net/server-sync if it is mounted. Returning
			return True
		'''

		self.local_dirs={}
		#sorted!!!
		
		self.parse_local_folders_conf()
		
		#path,perm,acl
		
		for item in sorted(self.local_dirs.keys()):
			
			self.dprint("Checking %s configuration..."%item)
			path=self.local_dirs[item]["path"]
			try:
				user = int(self.local_dirs[item]["owner"])
			except:
				user = int(pwd.getpwnam(self.local_dirs[item]["owner"]).pw_uid)
			try:
				group = int(self.local_dirs[item]["group"])
			except:
				group = int(grp.getgrnam(self.local_dirs[item]["group"]).gr_gid)
			if not os.path.exists(path):
				print("\t* Creating path %s ..."%path)
				try:
					os.makedirs(path)
					prevmask=os.umask(0)
					os.chmod(path,int(str(self.local_dirs[item]["perm"]),8))
					os.lchown(path,user,group)
					os.umask(prevmask)
				except Exception as e:
					print("!!",e,path)
		
				
			
			try:	
				info=self.get_acl_info(path)['return']
				info=self.get_missing_acl_conf(info)['return']
				
				if ( os.lstat(path).st_uid != user ) or (os.lstat(path).st_gid != group):
					os.lchown(path,user,group)
					
				tmp=oct(stat.S_IMODE(os.lstat(path).st_mode)).lstrip("0o")

				if tmp!=info[path]["perm"]:
					prevmask=os.umask(0)
					perm=info[path]["perm"]
					os.chmod(path,int(str(perm),8))
					os.umask(prevmask)

				for acl in info[path]["acl"]:
					print("\t* Setting acls to " + path + " ...")
					options,value=acl
					self.set_acl(path,options,value,recursive)
					
			except Exception as e:
				print (e)
			

	#def check_local_folders
	
	def set_acl(self,path,options,value,recursive=False):
		
		if recursive:
			recursive="-R"
		else:
			recursive=""
	
		if type(path)==bytes:
			path=path.decode("utf-8")
		
		cmd_str="setfacl %s %s %s '%s'"%(recursive,options,value,path)
		
		self.dprint(cmd_str)
		
		os.system(cmd_str.encode("utf-8"))
		#here goes executing command
		
	#def set_acl
	
	def get_shared_folders(self):
		
		self.remote_dirs={}
		
		try:
			srv_ip=self.core.get_variable("SRV_IP")["return"]
		except:
			srv_ip=None
			
		if srv_ip!=None:
			sp=sambaparser.SambaParser()
			for item in os.listdir(self.SMB_CONF_FOLDER):
				
				f=self.SMB_CONF_FOLDER+item
				sp.read(f)
				for key in sp.conf:
					if key!=None:
						try:
							line="//"+srv_ip+"/"+key
							self.remote_dirs[line]={}
							self.remote_dirs[line]["dst"]=sp.conf[key]["mount_point"]
							self.remote_dirs[line]["fstype"]="cifs"
						except Exception as e:
							print(e)
							
						
		#Old n4d: return self.remote_dirs
		return n4d.responses.build_successful_call_response(self.remote_dirs)

		
	#def check_shared_folders
	
	
	def dprint(self,item):
		
		if self.debug:
		
			try:
				print("[NetFoldersManager] " + str(item) )
			except:
				pass
		
	#def dprint

	def get_acl_group_filtered(self,group):
		result = []
		path = self.LOCAL_CONF_FOLDER + os.path.sep + group.lower()
		if os.path.exists(path):
			aux_file = open(path)
			list_acl = json.load(aux_file)
			
			for items in list_acl.values():
				for x in items['acl']:
					if '-d' in x[0]:
						x[0] = u'-m'
						result.append(x)
			aux_file.close()
		#Old n4d: return result
		return n4d.responses.build_successful_call_response(result)
		
		
	def is_dir_workable(self,current_dir,banned_list):
		
		for dir in banned_list:
			
			if dir in current_dir:
				
				#Old n4d: return False
				return n4d.responses.build_successful_call_response(False)
				
				
		#Old n4d: return True
		return n4d.responses.build_successful_call_response(True)
		
	#def is_dir_workable


	def restore_acls(self):
		
		try:
		
			self.local_folders={}
			self.local_dirs={}
			self.parse_local_folders_conf()
			
			dirs_to_process={}
			
			for item in self.local_dirs:
				dirs_to_process[self.local_dirs[item]["path"]]=""
				
			

			for item in self.local_dirs:
				
				
					owner=self.local_dirs[item]["owner"]
					group=self.local_dirs[item]["group"]
					path=self.local_dirs[item]["path"]
					perm=self.local_dirs[item]["perm"]
					acls=self.local_dirs[item]["acl"]
					file_acls=[]
					
					dirs_to_process.pop(path)
					
					for acl in acls:
						options,value=acl
						if "-d" not in options:
							file_acls.append(acl)
							
					'''
					print item
					print "\t",owner,group,path,perm
					print "\t",file_acls
					'''
					
					for walk_item in os.walk(path):
						dir,subdirs,files=walk_item
						
						if self.is_dir_workable(dir,dirs_to_process)['status'] == 0:
							#print dir
							#print "\t",files
							dir=dir.encode("utf-8")	
							cmd="setfacl -k -b '" + dir + "'"
							os.system(cmd)
							
							prevmask=os.umask(0)
							os.chmod(path,int(str(perm),8))
													
							for f in files:
								for acl in file_acls:
									options,value=acl
									if type(f)==type(u""):
										f=f.encode("utf-8")
									
									self.set_acl(dir+"/"+f,options,value)
								self.set_acl(dir+"/"+f,"-m","m:rw")
							
							for acl in acls:
								options,value=acl
								self.set_acl(dir,options,value)
								
							os.umask(prevmask)
							
							
			#return [True,""]
			return n4d.responses.build_successful_call_response(True)
			
			
		except Exception as e:
			#return [False,str(e)]
			return n4d.responses.build_failed_call_response(-10,str(e))
		
		
	#def restore_acls
	
	def restore_acls_via_thread(self):
		
		if not self.acl_thread.is_alive():
			
			self.acl_thread=threading.Thread(target=self.restore_acls)
			self.daemon=True
			self.acl_thread.start()
			
			
		return True
		
		
	#def restore_acls_via_thread
	
	def is_acl_thread_alive(self):
		
		return self.acl_thread.is_alive()

	#def is_acl_thread_alive

	def restore_teacher_access(self,student):

		folders=["/net/server-sync/home/students/%s/Desktop","/net/server-sync/home/students/%s/Documents"]
		if pwd.getpwnam(student).pw_uid > 20000:

			print ("Fixing %s ..."%student)

			for folder in folders:

				os.system("chown '%s':nogroup '%s'"%(student,folder%student))
				os.system("chmod 770 -R '%s'"%(folder%student))

			#Old n4d: return True
			return n4d.responses.build_successful_call_response(True)

		else:
			#Old n4d: return False
			return n4d.responses.build_successful_call_response(False)


	#def restore_teacher_access

	
#class NetFoldersManager

if __name__=="__main__":
	
	nfm=NetFoldersManager()
	#nfm.restore_acls()

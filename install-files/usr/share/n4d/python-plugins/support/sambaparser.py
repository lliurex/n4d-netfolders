
class SambaParser:
	
	def __init__(self):
		
		self.conf={}
		self.strip_values=[" ","\t","\n"]
		
	#def init
	
	def read(self,file):
		
		self.conf={}
		f=open(file)
		lines=f.readlines()
		f.close()
		self.parse_lines(lines,file)
		
	#def read
	
	def parse_lines(self,lines,path,section=None):
		
		count=1
		if not self.conf.has_key(section):
			self.conf[section]={}
		
		for line in lines:

			for strip_value in self.strip_values:
				line=line.lstrip(strip_value)
			
			if line.find("#")!=0 and line.find(";")!=0 and line.find("[")!=0 and  line.find("=")!=-1:
				
				for strip_value in self.strip_values:
					line=line.rstrip(strip_value)
					
					
				tmp=line.split("=")
				
				try:
					key,value=tmp
				except Exception as e:
					if len(tmp)>2:
						key=tmp[0]
						value="=".join(tmp[1:])
					else:
						return(False,"Malformed option in line " + str(count) + ":\n" + line)
				
				for strip_value in self.strip_values:
					key=key.rstrip(strip_value)
					
					
					
				for strip_value in self.strip_values:
					value=value.lstrip(strip_value)
					
				
				'''
				if 'include' in key:
					
					self.conf[section][key]={}
					self.conf[section][key]['value'] = value
					self.conf[section][key]['path'] = path
					
				'''
				self.conf[section][key]=value
				
				
			if line.find("[")==0:
				
				for strip_value in self.strip_values:
					line=line.rstrip(strip_value)
				
				
				if line.find("]")==len(line)-1:
					section=line[1:line.find("]")]
				
					self.conf[section]={}
					self.conf[section]['x-lliurex-path'] = path
				else:
					#print line.find("]"),len(line)
					return (False,"Malformed section in line " + str(count) + ":\n" + line)
					
				
		
		return True
			
		
		
	#def parse_lines
	
	
	
#class SambaParser
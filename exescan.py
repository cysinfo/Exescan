#!/usr/bin/env python
import sys,pefile,re,peutils,os
from hashlib import md5,sha1,sha256

'''

Author: Amit Malik
E-Mail: m.amit30@gmail.com
(C)2011

Version: 2.6
Last Update: 16-09-2012 

'''


def help():
	print
	print "Usage: prog [option] file/Directory"
	print "For eg: exescan.py -a malware.exe/malware"
	print "-a","advanced scan with anomaly detection"
	print "-b","display basic information"
	print "-m","scan for commonly known malware APIs"
	print "-i","display import/export table"
	print "-p","display PE header"
	print


def greet():
	log("\t\t**********************************************************")
	log("\t\t**           Author: Amit Malik (m.amit30@gmail.com)    **")
	log("\t\t**           http://www.SecurityXploded.com             **")
	log("\t\t**                                                      **")
	log("\t\t**********************************************************")	
	
	
def log(data):
		global handle
		print data
		data = data
		nextline = "\n"
		handle.write(data)
		handle.write(nextline)
		return
		
class ExeScan():
	def __init__(self,pe,file):
		self.pe = pe
		self.file = file
		self.MD5 = None
		self.SHA1 = None
		self.SHA256 = None
		self.data = None
		
	def hashes(self):
		f = open(self.file,"rb")
		self.data = f.read()
		self.MD5 = md5(self.data).hexdigest()
		self.SHA1 = sha1(self.data).hexdigest()
		self.SHA256 = sha256(self.data).hexdigest()
		f.close()
		return (self.MD5,self.SHA1,self.SHA256,self.data) 
	
	def header(self):
		#header information check
		file_header = self.pe.FILE_HEADER.dump()
		log("\n")
		for i in file_header:
			log(i)
		nt_header = self.pe.NT_HEADERS.dump()
		log("\n")
		for i in nt_header:
			log(i)
		optional_header = self.pe.OPTIONAL_HEADER.dump()
		log("\n")
		for i in optional_header:
			log(i)
		log("\n")
		for i in self.pe.OPTIONAL_HEADER.DATA_DIRECTORY:
				i = i.dump()
				log("\n")
				for t in i:
					log(t)
		log("\n")
		for section in self.pe.sections:
			log("Name: %s\n" % section.Name)
			log('\tVirtual Size:            0x%.8x' % section.Misc_VirtualSize)
			log('\tVirtual Address:         0x%.8x' % section.VirtualAddress)
			log('\tSize of Raw Data:        0x%.8x' % section.SizeOfRawData)
			log('\tPointer To Raw Data:     0x%.8x' % section.PointerToRawData)
			log('\tPointer To Relocations:  0x%.8x' % section.PointerToRelocations)
			log('\tPointer To Linenumbers:  0x%.8x' % section.PointerToLinenumbers)
			log('\tNumber Of Relocations:   0x%.8x' % section.NumberOfRelocations)
			log('\tNumber Of Linenumbers:   0x%.8x' % section.NumberOfLinenumbers)
			log('\tCharacteristics:         0x%.8x\n' % section.Characteristics)
			
				
		
	def anomalis(self):
		log("\n[+] Anomalies Check\n")
		
		# Entropy based check.. imported from peutils
		pack = peutils.is_probably_packed(self.pe)
		if pack == 1:
			log("\t[*] Based on the sections entropy check! file is possibly packed")
		
		# SizeOfRawData Check.. some times size of raw data value is used to crash some debugging tools.
		nsec = self.pe.FILE_HEADER.NumberOfSections
		for i in range(0,nsec-1):
			if i == nsec-1:
				break
			else:
				nextp = self.pe.sections[i].SizeOfRawData + self.pe.sections[i].PointerToRawData
				currp = self.pe.sections[i+1].PointerToRawData
				if nextp != currp:
					log("\t[*] The Size Of Raw data is valued illegal! Binary might crash your disassembler/debugger")
					break
				else:
					pass
					
		# Non-Ascii or empty section name check	
		for sec in self.pe.sections:
			if not re.match("^[.A-Za-z][a-zA-Z]+",sec.Name):
				log("\t[*] Non-ascii or empty section names detected")
				break;
		
		# Size of optional header check
		if self.pe.FILE_HEADER.SizeOfOptionalHeader != 224:
			log("\t[*] Illegal size of optional Header")
		
		# Zero checksum check
		if self.pe.OPTIONAL_HEADER.CheckSum == 0:
			log("\t[*] Header Checksum is zero!")
		
		# Entry point check	
		enaddr = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
		vbsecaddr = self.pe.sections[0].VirtualAddress
		ensecaddr = self.pe.sections[0].Misc_VirtualSize
		entaddr = vbsecaddr + ensecaddr
		if enaddr > entaddr:
			log("\t[*] Enrty point is outside the 1st(.code) section! Binary is possibly packed")
		
		# Numeber of directories check	
		if self.pe.OPTIONAL_HEADER.NumberOfRvaAndSizes != 16:
			log("\t[*] Optional Header NumberOfRvaAndSizes field is valued illegal")
		
		# Loader flags check	
		if self.pe.OPTIONAL_HEADER.LoaderFlags != 0:
			log("\t[*] Optional Header LoaderFlags field is valued illegal")
			
		# TLS (Thread Local Storage) callback function check
		if hasattr(self.pe,"DIRECTORY_ENTRY_TLS"):
			log("\t[*] TLS callback functions array detected at 0x%x" % self.pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks)
			callback_rva = self.pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - self.pe.OPTIONAL_HEADER.ImageBase
			log("\t[*] Callback Array RVA 0x%x" % callback_rva)



	def base(self,check):
		log("\n[+] Signature [Compiler/Packer]\n")
		if check:
			for i in check:
				log('\t%s' % i)
		else:
			log("\t[*] No match found.\n")
				
		log("\n[+] Address of entry point	: 0x%.8x\n" % self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)
		log("[+] Image Base Address		: 0x%.8x\n" % self.pe.OPTIONAL_HEADER.ImageBase)
		log("[+] Sections")
		for section in self.pe.sections:
			log("\tName: %s\t" % section.Name.strip() + "Virtual Address: 0x%.8x\t" % section.VirtualAddress + "Size: 0x%.8x\t" % section.Misc_VirtualSize + "Entropy: %f" % section.get_entropy())
			

	def importtab(self):
		if hasattr(self.pe,"DIRECTORY_ENTRY_IMPORT"):
			log("\n[+] Imports\n")
			for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
				log('\n[-] %s\n' % entry.dll)
				for imp in entry.imports:
					log('\t0x%.8x\t%s' % (imp.address, imp.name))
				
	def exporttab(self):
		if hasattr(self.pe,"DIRECTORY_ENTRY_EXPORT"):
			log("\n[+] Exports\n")
			for entry in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
				log('\t0x%.8x\t%s' % (entry.address, entry.name))
				
	def malapi(self,MALAPI,str):
		dict = {}
		log("\n[+] Following expected Malware APIs are Detected\n")
		log("\n\t[-] Import Table\n")
		for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
			for imp in entry.imports:
				dict[imp.name] = imp.address
		for m in MALAPI:
			m = m.strip()
			if m in dict.keys():
				log("\t\tIA: 0x%08x\t%s" % (dict[m],m))
		log("\n\t[-] Entire Executable\n")
		for m in MALAPI:
			i = 0
			m = m.strip()
			try:
				for s in str:
					if re.search(m,s):
						d = m
						i = i + 1
				if d == m:
					log("\t\t %d times\t%s" % (i,d))
			except:
				pass
				

				
class StringAndThreat():
	'''
		extract strings from binary.
		
	'''
	def __init__(self,MD5,data):
		self.MD5 = MD5
		self.data = data
		self.handle = None
		
	def StringE(self):
		name = "strings_"+self.MD5+".txt"
		name = os.path.join(self.MD5,name)
		if os.path.exists(name):
			return
		self.handle = open(name,'a')
		headline = "\t\t\tStrings-%s\n\n" % self.MD5
		self.handle.write(headline)
		for m in re.finditer("([\x20-\x7e]{3,})", self.data):
			self.handle.write(m.group(1))
			self.handle.write("\n")
		return
		


def main_s(pe,ch,f,name):
	global handle
	exescan = ExeScan(pe,name)
	(MD5,SHA1,SHA256,data) = exescan.hashes()
	stx = StringAndThreat(MD5,data)
	# store reports in folders
	if os.path.exists(MD5):
		report_name = str(MD5)+".txt"
		report_name = os.path.join(MD5,report_name)
	else:
		os.mkdir(MD5)
		report_name = str(MD5)+".txt"
		report_name = os.path.join(MD5,report_name)
	handle = open(report_name,'a')
	greet()
	log("\n\n[+] File: %s" % name)
	log("\n\t[*] MD5 	: %s" % MD5)
	log("\t[*] SHA-1 	: %s" % SHA1)
	log("\t[*] SHA-256	: %s" % SHA256)
	#check file type (exe, dll)
	if pe.is_exe():
		log("\n[+] File Type: EXE")
	elif pe.is_dll():
		log("\n[+] File Type: DLL")
	strings = f.readlines()
	mf = open("API.txt","r")
	MALAPI = mf.readlines()
	signature  = peutils.SignatureDatabase("userdb.txt")
	check = signature.match_all(pe,ep_only = True)
	if ch == "-i":
		exescan.base(check)
		exescan.importtab()
		exescan.exporttab()
	elif ch == "-b":
		exescan.base(check)
	elif ch == "-m":
		exescan.base(check)
		exescan.malapi(MALAPI,strings)
	elif ch == "-p":
		exescan.base(check)
		exescan.header()
	elif ch == "-a":
		exescan.base(check)
		exescan.anomalis()
		exescan.malapi(MALAPI,strings)
		stx.StringE()
	else:
		print
	mf.close()
	handle.close()
	return MD5
			
def main():
	if len(sys.argv) < 3:
		help()
		sys.exit(0)
	ch = sys.argv[1]
	fname = sys.argv[2]
	if os.path.isdir(fname):
		filelist = os.listdir(fname)
		for name in filelist:
			try:
				name = os.path.join(fname,name)
				pe = pefile.PE(name)
				f = open(name,"rb")
				new_name = main_s(pe,ch,f,name)
				f.close()
				pe.__data__.close()
				try:
					new_name = new_name + ".bin"
					new_name = os.path.join(fname,new_name)
					os.rename(name,new_name)
				except:
					pass
			except:
				pass
	else:
		try:
			fname = os.path.realpath(fname)
			print fname
			pe = pefile.PE(fname)
			f = open(fname,"rb")
			new_name = main_s(pe,ch,f,fname)
			f.close()
			pe.__data__.close()
			try:
				new_name = new_name + ".bin"
				os.rename(fname,new_name)
			except:
				pass
		except Exception, WHY:
			print "\nInvalid file\n"
			print "Verbose: %s" % WHY
			sys.exit(0)

if __name__ == '__main__':
		main()
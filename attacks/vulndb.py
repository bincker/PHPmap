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
#
#--

import sqlite3,os,sys

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
				
class VulnDB:
	def connect(self):
		conn = sqlite3.connect('attacks/phpmap3.db')
		cursor = conn.cursor()
		return conn,cursor
		
	def is_vuln(self,type,**kwargs):
		conn,cursor = self.connect()
		if (type == 'form') or (type == 'crawl'):
			for key in kwargs:
				if (key == 'url'): url = kwargs[key]
				if (key == 'param'): param = kwargs[key]
				if (key == 'originalvalue'): originalValue = kwargs[key]
				if (key == 'payload'): payload = kwargs[key]
				if (key == 'formName'): formName = kwargs[key]
				if (key == 'method'): method = kwargs[key]	
		if (type == 'get'):
			for key in kwargs:
				if (key == 'url'): url = kwargs[key]
				if (key == 'param'): param = kwargs[key]
				if (key == 'originalvalue'): originalValue = kwargs[key]
				if (key == 'payload'): payload = kwargs[key]
				formName = "url"
				method = type
		cursor.execute("SELECT * FROM vulndb WHERE url = ?", [url])
		result = cursor.fetchone()
		if result:
			return True, result
		else:
			return False, None
		
	def new_vuln(self,type,**kwargs):
		conn,cursor = self.connect()
		if (type == 'form') or (type == 'crawl'):
			for key in kwargs:
				if (key == 'url'): url = kwargs[key]
				if (key == 'param'): param = kwargs[key]
				if (key == 'originalvalue'): originalValue = kwargs[key]
				if (key == 'payload'): payload = kwargs[key]
				if (key == 'formName'): formName = kwargs[key]
				if (key == 'method'): method = kwargs[key]	
		if (type == 'get'):
			for key in kwargs:
				if (key == 'url'): url = kwargs[key]
				if (key == 'param'): param = kwargs[key]
				if (key == 'originalvalue'): originalValue = kwargs[key]
				if (key == 'payload'): payload = kwargs[key]
				formName = "url"
				method = type
		cursor.execute("INSERT INTO vulndb VALUES (?,?,?,?,?,?)", (url,param,originalValue,payload,formName,method))
		conn.commit()
		conn.close()
		return
		
	def clear_vulns(self):
		conn,cursor = self.connect()
		cursor.execute("DELETE from vulndb")
		conn.commit()
		conn.close()
		return
		

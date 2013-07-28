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

import urllib2, os, sys
from bs4 import BeautifulSoup
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
import get

class FRMFind:
	def search(self,url,basic,cookie):
		results_get,results_post = {},{}
		soup = get.HTTP().getPage(url,basic,cookie)
		if soup is 0:
			return None,None
		for formTag in soup.findAll('form'):
			if formTag.has_key('action'):
				if (formTag['action'] != "#"):
					if formTag.has_key('method') and formTag['method'] == "post":
						for i in xrange(0,len(soup.findAll('form'))):
							for inputTag in soup.findAll('form')[i].findAll('input'):
								try:
									try:
										results_post[formTag['action']+str(i)] = {inputTag['name']:inputTag['value']}
									except:
										continue
								except:
									try:
										results_post[formTag['action']+str(i)] = {inputTag['name']:0}
									except:
										continue
					else:
						for i in xrange(0,len(soup.findAll('form'))):
							for inputTag in soup.findAll('form')[i].findAll('input'):
								try:
									results_get[formTag['action']+str(i)] = {inputTag['name']:inputTag['value']}
								except:
									try:
										results_get[formTag['action']+str(i)] = {inputTag['name']:0}
									except:
										continue
								i+=1
		return results_get,results_post

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

import sys,os
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

class Crawl:
	def crawl(self,url,depth,restrict,basic,cookie):
		soup = get.HTTP().getPage(url,basic,cookie)
		globalqueue,urlqueue = [],[]
		for formTag in soup.findAll('a'):
			if formTag.has_key('href') and (formTag['href'] != "#"):
					if (restrict is not None):
						if (restrict not in formTag['href']):
							urlqueue.append(formTag['href'])
						else:
							continue
					else:
						urlqueue.append(formTag['href'])
		for urli in urlqueue:
			soup = get.HTTP().getPage(urli,basic,cookie)
			if soup is not 0:
				for formTag in soup.findAll('a'):
					if formTag.has_key('href') and (formTag['href'] != "#"):
						if (restrict is not None):
							if (restrict not in formTag['href']):
								globalqueue.append(formTag['href'])
							else:
								continue
						else:
							globalqueue.append(formTag['href'])	
		dupeFilter = []					
		for url in globalqueue:
			if url not in dupeFilter:
				dupeFilter.append(url)
		return dupeFilter

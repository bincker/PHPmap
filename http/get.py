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

from bs4 import BeautifulSoup
import urllib2, base64

class HTTP:	
	def getPage(self,url,basic,cookie):
		request = urllib2.Request(url)
		if (basic is not None and cookie is None):
			try:
				request.add_header("Authorization", "Basic %s" % base64.b64encode("%s:%s" % (basic.split(":")[0],basic.split(":")[0])).replace("\n",""))
			except:
				print "[*] userpass not in valid format (ex username:password)"
		elif (cookie is not None and basic is None):
			try:
				request.add_header('Cookie', cookie)
			except:
				print "[*] cookie not in valid format"
		elif (cookie is not None and basic is not None):
			print "[*] can not use Cookie(s) and Basic Auth at the same time"
		try:
			page = urllib2.urlopen(request)
			try:
				soup = BeautifulSoup(markup=page.read(),features='html')
			except:
				print "[*] could not parse page"
				soup = 0
		except:
			print "[*] error grabbing page.."
			soup = 0
			
		if (soup is not 0): return soup
		else: return 0

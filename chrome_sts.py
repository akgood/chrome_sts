"""
Google Chrome 'Strict Transport Security' Config Editor

Example Usage:

check to see if www.facebook.com (or facebook.com, with the
'include_subdomains' flag) has an STS policy set:

    $ python chrome_sts.py -g www.facebook.com

enable an STS policy for www.facebook.com:

    $ python chrome_sts.py -s www.facebook.com

enable an STS policy for eff.org and all subdomains of eff.org:

    $ python chrome_sts.py -s --include-subdomains eff.org

remove STS policy for www.google.com (note: this will *only* remove a
policy for 'www.google.com', not 'google.com' even if the policy for
'google.com' has the 'include_subdomains' flag enabled):

    $ python chrome_sts.py -r www.google.com

Background:

Strict Transport Security is a proposed mechanism by which websites
can indicate that they should only be accessed over secure (HTTPS)
connections. This is accomplished by the addition of a new HTTP header
'Strict-Transport-Security', which, when present, instructs browsers
to never contact that site via HTTP again (up to some expiration
time).

For more details, see:
http://lists.w3.org/Archives/Public/www-archive/2009Sep/att-0051/draft-hodges-strict-transport-sec-05.plain.html

There are two major problems with this approach:

(1) Except in the case of a very careful user (in which case, Strict
    Transport Security may not provide much benefit anyway), the
    initial communication of the 'Strict-Transport-Security'
    information will occur over an insecure (HTTP) channel, and is
    thus prone to manipulation. Even with this weakness, STS does
    still provide a significant benefit; an attacker's window to
    attack is considerably narrowed to being only the first time a
    user accesses a site.

    Google proposes to remedy this in part by distributing a
    pre-installed list of STS domains. Currently, this list is
    hardcoded and only includes ~3 such domains, two of which are
    PayPal. This is a start, but not much of one...

(2) It requires the cooperation of site operators. Some sites
    (e.g. Facebook), while offering a secure option, would most likely
    prefer more users continue using the less secure (HTTP) option, as
    SSL places a significant additional burden on server resources.

So, there needs to be an option by which users can set "SSL-only"                                                                                                                               
policies as well. The EFF recently released a Firefox extension                                                                                                                                 
("HTTPS Everywhere") which does just that (as well as grafting                                                                                                                                  
Strict-Transport-Security support onto Firefox, which doesn't support                                                                                                                           
it natively yet). However, there doesn't really appear to be a good                                                                                                                             
option for Chrome yet. This is a crude attempt at starting to fix                                                                                                                               
that...                                                                                                                                                                                                                                                                                                                                                                              

When Google Chrome receives a 'Strict-Transport-Security' header, it
stores the configuration in a JSON file 'TransportSecurity' in its
user profile directory. Sites are indexed by SHA-256 hashes, so it
is impossible to enumerate all sites for which STS settings exist.

However, we can add or view configurations for specific sites                                                                                                                                   
(though, note that any sites which provide STS headers will probably                                                                                                                            
override any custom settings). This simple utility does just that.                                                                                                                              
                                                                                                                                                                                                
This script has only been tested so far with Google Chrome 5.0.375.99                                                                                                                           
on Mac OS X. (and not very thoroughly, at that)                                                                                                                                                 

TODO:
* friendlier output
* come up with some way to clarify when a 'get' returns a
  higher-level domain (with 'include_subdomains' set)
* ...?
"""

import hashlib, base64, json, platform, os.path, sys, time
from optparse import OptionParser

def dns_form(name):
    """Converts a dotted hostname to 'DNS form', as indicated by the
    Chromium source code (i.e. single-byte length field preceding
    each component of the domain name)"""

    components = name.split('.')
    dns_components = [chr(len(comp)) + comp for comp in components]
    return ''.join(dns_components)

def sts_key(name):
    """Return the key used by Chrome to index a domain name in the
    TransportSecurity JSON dictionary. The key is a base64-encoded
    SHA-256 digest of the "DNS Form" of the domain name"""

    digest = hashlib.sha256(dns_form(name) + '\0').digest()
    return base64.b64encode(digest)

def get_profile_path():
    """Attempt to guess the Google Chrome profile directory based
    on the operating system. This is extremely crude and probably
    could be done better"""

    path = None

    if platform.system() == 'Darwin':
        path = os.path.expanduser('~/Library/Application Support/Google/Chrome/Default')
    elif platform.system() == 'Windows':
        # XXX Will apparently only work on Vista+.
        # better (maybe?) would be to use ctypes to call into shell32.dll
        # (or figure out what chrome itself does?)
        path = os.environ['LOCALAPPDATA'] + '\\Google\\Chrome\\User Data\\Default'
    # XXX no linux support at all (yet?). Hopefully linux users
    # know where their chrome profile is stored...

    if path and os.path.exists(path):
        return path

    return None

def get_site_conf(sts_dict, name):
    # try for an exact match
    site_conf = sts_dict.get(sts_key(name))
    if site_conf:
        return (name, site_conf)

    # see if any 'superdomain' has the 'include_subdomains' key set
    components = name.split('.')
    for i in xrange(0, len(components)):
        name_part = '.'.join(components[i:len(components)])
        site_conf = sts_dict.get(sts_key(name_part))
        if site_conf and site_conf.get('include_subdomains'):
            return (name_part, site_conf)

    return (name, None)

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option('-p', '--profile-dir', dest='profile_dir')
    parser.add_option('-s', '--set', action='store_true', dest='set')
    parser.add_option('-g', '--get', action='store_true', dest='get')
    parser.add_option('-r', '--remove', action='store_true', dest='remove')
    parser.add_option('--include-subdomains', action='store_true', dest='include_subdomains')
    (options, args) = parser.parse_args()

    # validate
    if len(args) != 1:
        parser.print_usage()
        sys.exit(-1)
    if (int(bool(options.set)) + int(bool(options.get)) + int(bool(options.remove))) > 1:
        print '-s, -g, and -r are mutually exclusive!'
        sys.exit(-1)

    # locate TransportSecurity config file
    profile_dir = options.profile_dir
    if not profile_dir:
        profile_dir = get_profile_path()
    if not profile_dir:
        print 'My crude, hackish locator routine was unable to locate your Google Chrome profile.'
        print 'Please pass it manually using the \'-p\' option.'
        sys.exit(-1)
    sts_filename = os.path.join(profile_dir, 'TransportSecurity')

    # read STS configuration
    sts_dict = {}
    if os.path.exists(sts_filename):
        with open(sts_filename, 'r') as sts_fp:
            sts_dict = json.load(sts_fp)

    # perform requested action
    if options.set:
        site_conf = {
            'expiry': float(0x7FFFFFFF), # far in the future
            'created': time.time(),
            'mode': 'strict',
            'include_subdomains': bool(options.include_subdomains)
            }
        sts_dict[sts_key(args[0])] = site_conf
        with open(sts_filename, 'w') as sts_fp:
            json.dump(sts_dict, sts_fp, indent=4)
    elif options.remove:
        key = sts_key(args[0])
        if key in sts_dict:
            del sts_dict[key]
            with open(sts_filename, 'w') as sts_fp:
                json.dump(sts_dict, sts_fp, indent=4)
    else:
        site_name, config = get_site_conf(sts_dict, args[0])
        print '%s:' % site_name
        if config:
            print json.dumps(config, indent=4)
        else:
            print 'No configuration exists for that site'


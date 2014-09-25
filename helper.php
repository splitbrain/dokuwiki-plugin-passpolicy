<?php
/**
 * DokuWiki Plugin passpolicy (Helper Component)
 *
 * Check password policies and generate random passwords accordingly
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Andreas Gohr <andi@splitbrain.org>
 */

// must be run within Dokuwiki
if(!defined('DOKU_INC')) die();

class helper_plugin_passpolicy extends DokuWiki_Plugin {

    /** @var int number of character pools that have to be used at least */
    public $min_pools = 1;

    /** @var int minimum length of the password (bytes) */
    public $min_length = 6;

    /** @var string what type of password generation to use? */
    public $autotype = 'random';

    /** @var int minimum bit strength auto generated passwords should have */
    public $autobits = 64;

    /** @var array allowed character pools */
    public $usepools = array(
        'lower'   => true,
        'upper'   => false,
        'numeric' => true,
        'special' => false
    );
    
    /** @var string path to pass history dir  */
    public $passhistorydir = null;
    

    /** @var int number of consecutive letters that may not be in the username, 0 to disable */
    public $usernamecheck = 0;

    /** @var int policy violation error */
    public $error = 0;

    /** @var array the different pools to use when generating passwords */
    public $pools = array(
        'lower'   => 'abcdefghijklmnopqrstuvwxyz',
        'upper'   => 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        'numeric' => '0123456789',
        'special' => '!"$%&/()=?{[]}\\*+~\'#,;.:-_<>|@'
    );

    protected $wordlist = array();
    protected $wordlistlength = 0;
    protected $msgshown = false;

    const LENGTH_VIOLATION   = 1;
    const POOL_VIOLATION     = 2;
    const USERNAME_VIOLATION = 4;
    const OLDPASS_VIOLATION  = 8;

    /**
     * Constructor
     *
     * Sets the policy from the DokuWiki config
     */
    public function __construct() {
    	global $conf;
    	
        $this->min_length    = $this->getConf('minlen');
        $this->min_pools     = $this->getConf('minpools');
        $this->usernamecheck = $this->getConf('user');
        $this->autotype      = $this->getConf('autotype');
        $this->autobits      = $this->getConf('autobits');
        $this->oldpass       = $this->getConf('oldpass');

        $this->passhistorydir = $conf['metadir'].'/_passhistory/';
        
        $opts = explode(',', $this->getConf('pools'));
        if(count($opts)) { // ignore empty pool setups
            $this->usepools = array();
            foreach($opts as $pool) {
                $this->usepools[$pool] = true;
            }
        }
        if($this->min_pools > count($this->usepools)) $this->min_pools = $this->usepools;
    }

    /**
     * Generates a random password according to the backend settings
     *
     * @param string $username
     * @param int    $try internal variable, do not set!
     * @throws Exception when the generator fails to create a policy compliant password
     * @return bool|string
     */
    public function generatePassword($username, $try = 0) {
        if($this->autotype == 'pronouncable') {
            $pw = $this->pronouncablePassword();
            if($pw && $this->checkPolicy($pw, $username)) return $pw;
        }

        if($this->autotype == 'phrase') {
            $pw = $this->randomPassphrase();
            if($pw && $this->checkPolicy($pw, $username)) return $pw;
        }

        $pw = $this->randomPassword();
        if($pw && $this->checkPolicy($pw, $username)) return $pw;

        // still here? we might have clashed with the user name by accident
        if($try < 3) return $this->generatePassword($try++);

        // still here? now we have a real problem
        throw new Exception('can\'t create a random password matching the password policy');
    }

    /**
     * Gives a human readable explanation of the current policy as plain text.
     *
     * @return string
     */
    public function explainPolicy() {
        // we need access to the settings.php translations for the pool names
        // FIXME core should provide a way to access them
        global $conf;
        $lang = array();
        $path = dirname(__FILE__);
        @include($path.'/lang/en/settings.php');
        if($conf['lang'] != 'en') @include($path.'/lang/'.$conf['lang'].'/settings.php');

        // load pool names
        $confplugin = plugin_load('admin', 'config');
        $pools      = array();
        foreach($this->usepools as $pool => $on) {
            if($on) $pools[] = $lang['pools_'.$pool];
        }

        $text = '';
        if($this->min_length)
            $text .= sprintf($this->getLang('length'), $this->min_length)."<br>";
        if($this->min_pools)
            $text .= sprintf($this->getLang('pools'), $this->min_pools, join(', ', $pools))."<br>";
        if($this->usernamecheck == 1)
            $text .= $this->getLang('user1')."<br>";
        if($this->usernamecheck > 1)
            $text .= sprintf($this->getLang('user2'), $this->usernamecheck)."<br>";
        if($this->oldpass > 0)
            $text .= sprintf($this->getLang('oldpass'), $this->oldpass)."<br>";

        return trim($text);
    }

    /**
     * Checks a given password for policy violation
     *
     * @param string $pass true if the password validates against the policy
     * @param string $username
     * @return bool
     */
    public function checkPolicy($pass, $username) {
        $this->error = 0;

        // check length first:
        if(utf8_strlen($pass) < $this->min_length) {
            $this->error = helper_plugin_passpolicy::LENGTH_VIOLATION;
            return false;
        }

        $matched_pools = 0;
        if(!empty($this->usepools['lower'])) $matched_pools += (int) preg_match('/[a-z]/', $pass);
        if(!empty($this->usepools['upper'])) $matched_pools += (int) preg_match('/[A-Z]/', $pass);
        if(!empty($this->usepools['numeric'])) $matched_pools += (int) preg_match('/[0-9]/', $pass);
        if(!empty($this->usepools['special'])) $matched_pools += (int) preg_match('/[^A-Za-z0-9]/', $pass); // we consider everything else special
        if($matched_pools < $this->min_pools) {
            $this->error = helper_plugin_passpolicy::POOL_VIOLATION;
            return false;
        }

        if($this->usernamecheck && $username) {
            $pass2     = utf8_strtolower($pass);
            $username  = utf8_strtolower($username);

            // simplest case first
            if(utf8_stripspecials($pass2, '', '\._\-:\*') == utf8_stripspecials($username, '', '\._\-:\*')) {
                $this->error = helper_plugin_passpolicy::USERNAME_VIOLATION;
                return false;
            }

            // find possible chunks in the lenght defined in policy
            if($this->usernamecheck > 1) {
                $chunks = array();
                for($i = 0; $i < utf8_strlen($pass2) - $this->usernamecheck + 1; $i++) {
                    $chunk = utf8_substr($pass2, $i, $this->usernamecheck + 1);
                    if($chunk == utf8_stripspecials($chunk, '', '\._\-:\*')) {
                        $chunks[] = $chunk; // only word chars are checked
                    }
                }

                // check chunks against user name
                $chunks = array_map('preg_quote_cb', $chunks);
                $re     = join('|', $chunks);

                if(preg_match("/($re)/", $username)) {
                    $this->error = helper_plugin_passpolicy::USERNAME_VIOLATION;
                    return false;
                }
            }
        }
        
        //dbg($pass);
        if($this->oldpass > 0 && 
        	$oldPasswords = $this->getUserPassHistory($username)
        ) {
        	foreach($oldPasswords as $oldPassword) {
        		if(auth_verifyPassword($pass, $oldPassword)) {
					$this->error = helper_plugin_passpolicy::OLDPASS_VIOLATION;
        			return false;
        		}
        	}
	
        }

        return true;
    }

    /**
     * Creates a completely random password
     *
     * @return string
     */
    protected function randomPassword() {
        $num_bits   = $this->autobits;
        $output     = '';
        $characters = '';

        // always use these pools
        foreach(array('lower', 'upper', 'numeric') as $pool) {
            $pool_len = strlen($this->pools[$pool]);
            $output .= $this->pools[$pool][$this->rand(0, $pool_len - 1)]; // add one char already
            $characters .= $this->pools[$pool]; // add to full pool
            $num_bits -= $this->bits($pool_len);
        }

        // if specials are wanted, limit them to a sane amount of 3
        if(!empty($this->usepools['special'])) {
            $pool_len = strlen($this->pools['special']);
            $poolbits = $this->bits($pool_len);

            $sane = ceil($this->autobits / 25);
            for($i = 0; $i < $sane; $i++) {
                $output .= $this->pools['special'][$this->rand(0, $pool_len - 1)];
                $num_bits -= $poolbits;
            }
        }

        // now prepare the full pool
        $pool_len = strlen($characters);
        $poolbits = $this->bits($pool_len);

        // add random chars
        do {
            $output .= $characters[$this->rand(0, $pool_len - 1)];
            $num_bits -= $poolbits;
        } while($num_bits > 0 || strlen($output) < $this->min_length);

        // shuffle to make sure our intial chars are not necessarily at the start
        return str_shuffle($output);
    }

    /**
     * Creates a pronouncable password
     *
     * @return bool|string  the new password, false on error
     */
    protected function pronouncablePassword() {
        $num_bits = $this->autobits;

        // prepare speakable char classes
        $consonants = 'bcdfghjklmnprstvwz'; //consonants except hard to speak ones
        $vowels     = 'aeiou';
        $all        = $consonants.$vowels;
        $specials   = '!$%&=?.-_;,';

        // prepare lengths
        $c_len = strlen($consonants);
        $v_len = strlen($vowels);
        $a_len = $c_len + $v_len;

        // prepare bitcounts
        $c_bits = $this->bits($c_len);
        $v_bits = $this->bits($v_len);
        $a_bits = $this->bits($a_len);

        // prepare policy compliant postfix
        $postfix = '';
        if($this->usepools['numeric']) {
            $postfix .= $this->rand(10, 99);
            $num_bits -= $this->bits(99 - 10);
        }
        if($this->usepools['special']) {
            $spec_len = strlen($this->pools['special']);
            $postfix .= $this->pools['special'][rand(0, $spec_len - 1)];
            $num_bits -= $this->bits($spec_len);
        }

        // create words
        $output = '';
        do {
            $output .= $consonants[$this->rand(0, $c_len - 1)];
            $output .= $vowels[$this->rand(0, $v_len - 1)];
            $output .= $all[$this->rand(0, $a_len - 1)];

            $num_bits -= $c_bits;
            $num_bits -= $v_bits;
            $num_bits -= $a_bits;
        } while($num_bits > 0 || strlen($output) < $this->min_length);

        // now ensure policy compliance by uppercasing and postfixing
        if($this->usepools['upper']) $output = ucfirst($output);
        if($postfix) $output .= $postfix;

        return $output;
    }

    /**
     * Creates a passphrase from random words
     *
     * @author Michael Samuel
     * @author Solar Designer
     * @return string
     */
    protected function randomPassphrase() {
        $num_bits = $this->autobits;

        // prepare policy compliant prefix
        $prefix = '';
        if($this->usepools['numeric']) {
            $prefix .= $this->rand(0, 999);
            $num_bits -= $this->bits(999);
        }
        if($this->usepools['special']) {
            $spec_len = strlen($this->pools['special']);
            $prefix .= $this->pools['special'][rand(0, $spec_len - 1)];
            $num_bits -= $this->bits($spec_len);
        }

        // load the words to use
        $this->loadwordlist();
        $wordbits = $this->bits($this->wordlistlength);

        // generate simple all lowercase word phrase
        $output = '';
        do {
            $output .= $this->wordlist[$this->rand(0, $this->wordlistlength - 1)].' ';
            $num_bits -= $wordbits;
        } while($num_bits > 0 || strlen($output) < $this->min_length);

        // now ensure policy compliance by uppercasing and prefixing
        if($this->usepools['upper']) $output = ucwords($output);
        if($prefix) $output = $prefix.' '.$output;

        return trim($output);
    }

    /**
     * Return the number of bits in an integer
     *
     * @author Michael Samuel
     * @param int $number
     * @return int
     */
    protected function bits($number) {
        $bits = 0;

        while($number > 0) {
            $number >>= 1;
            $bits += 1;
        }

        return $bits;
    }

    /**
     * Random number generator using the best available source
     *
     * @author Michael Samuel
     * @param int $min
     * @param int $max
     * @return int
     */
    public function rand($min, $max) {
        $real_max = $max - $min;
        $mask     = (1 << $this->bits($real_max)) - 1;

        try {
            do {
                $bytes   = $this->trueRandomBytes(4);
                $unpack  = unpack("lnum", $bytes);
                $integer = $unpack["num"] & $mask;
            } while($integer > $real_max);
        } catch(Exception $e) {
            if(!$this->msgshown) {
                msg('No secure random generator available, falling back to less secure mt_rand()', -1);
                $this->msgshown = true;
            }
            return mt_rand($min, $max);
        }

        return $integer + $min;
    }

    /**
     * Return truly (pseudo) random bytes
     *
     * @author Mark Seecof
     * @link   http://www.php.net/manual/de/function.mt-rand.php#83655
     * @param int $bytes number of bytes to get
     * @throws Exception when no usable random generator is found
     * @return string binary random strings
     */
    protected function trueRandomBytes($bytes) {
        $strong = false;
        $rbytes = false;

        if(function_exists('openssl_random_pseudo_bytes')) {
            $rbytes = openssl_random_pseudo_bytes($bytes, $strong);
        }

        // If no strong SSL randoms available, try OS the specific ways
        if(!$strong) {
            // Unix/Linux platform
            $fp = @fopen('/dev/urandom', 'rb');
            if($fp !== false) {
                $rbytes = fread($fp, $bytes);
                fclose($fp);
            }

            // MS-Windows platform
            if(class_exists('COM')) {
                // http://msdn.microsoft.com/en-us/library/aa388176(VS.85).aspx
                try {
                    $CAPI_Util = new COM('CAPICOM.Utilities.1');
                    $rbytes    = $CAPI_Util->GetRandom($bytes, 0);

                    // if we ask for binary data PHP munges it, so we
                    // request base64 return value.  We squeeze out the
                    // redundancy and useless ==CRLF by hashing...
                    if($rbytes) $rbytes = md5($rbytes, true);
                } catch(Exception $ex) {
                    // fail
                }
            }
        }
        if(strlen($rbytes) < $bytes) $rbytes = false;

        if($rbytes === false) throw new Exception('No true random generator available');

        return $rbytes;
    }

    /**
     * loads the word list for phrase generation
     *
     * Words are taken from the wiki's own search index and are complemented with a
     * list of 4096 English words. This list comes from a passphrase generator
     * mentioned on sci.crypt, religious and possibly offensive words have been
     * replaced with less conflict laden words
     */
    protected function loadwordlist() {
        if($this->wordlistlength) return; //list already loaded

        // load one of the local word index files
        $indexer        = new helper_plugin_passpolicy__index();
        $this->wordlist = $indexer->getIndex('w', $this->rand(4, 6));
        $this->wordlist = array_filter($this->wordlist, 'utf8_isASCII'); //only ASCII, users might have trouble typing other things

        // add our own word list to fill up
        $this->wordlist += file(dirname(__FILE__).'/words.txt', FILE_IGNORE_NEW_LINES);
        $this->wordlistlength = count($this->wordlist);
    }
    
    
    /**
     * check if password is expired
     * 
     * @param string $user
     * @return boolean|timestamp timestamp when password is expired with expireing day
     */
    public function checkPasswordExpired($user=false) {
    	$dateStart = strtotime($this->getConf('date_start'));
    	
    	$datePassExpire = $this->getDatePassExpire($user);
    
    	if($datePassExpire && 
    		$datePassExpire >= $dateStart &&
    		$datePassExpire < time()
        ) {
    		return $datePassExpire;
    	} 
    	
    	return false;
    }
    
    /**
     * check if we have to warn the user about an expireing password
     * 
     * @param string $user
     * @return boolean|timestamp false or timestamp when the password will expire.
     */
    public function checkPasswordExpireWarn($user=false) {
    	$timespanWarn = intval($this->getConf('expirewarn'));
    	if(!$timespanWarn) return false;
    	
    	$dateStart = strtotime($this->getConf('date_start'));
    	
    	$datePassExpire = $this->getDatePassExpire($user);

    	if($datePassExpire && 
    		max(array($datePassExpire,$dateStart)) < (time() + $timespanWarn*3600*24)
        ) {
    		return max(array($datePassExpire,$dateStart));
    	} 
    	return false;
    	
    }
    
    /**
     * returns the date when the current password will expire, wont respect dateStart to extend the time
     * 
     * @param string $user
     * @return false or timestamp
     */
    protected function getDatePassExpire($user = false) {
    	$passChanged = $this->getPassHistoryChangeDate($user);
    	$dateStart = strtotime($this->getConf('date_start'));
    		 
    	if($passChanged) { //user has already changed password since plugin installation
    		$expire_interval = $this->getConf('expire') * 3600*24;
    		if($expire_interval) {//next password change will be then
    			$expireDate = $passChanged + $expire_interval;
    		} else {//no need to change password
    			$expireDate = false;
    		}
    	} else { //user has not changed password since plugin installation, password will expire at start date
    		$expireDate = $dateStart;
    	}
    
    	return $expireDate;	 
    }
    
    /**
     * returns the passHistory entry for a given user
     * 
     * @param string $user
     * @return NULL|boolean|array assotiative array 'date','pass'[]
     */
    protected function getUserPassHistory($user=false) {
    	if(!$user && $_SERVER['REMOTE_USER']) $user = $_SERVER['REMOTE_USER'];
    	
    	$passhistory = io_readFile($this->passhistorydir . utf8_encodeFN($user).'.txt');
    	if(!$passhistory) {
    		return false;
    	}
    	$passhistory = explode("\n", $passhistory);
    	  	 
    	if(is_array($passhistory)) {
    		$passhistory = array_slice($passhistory, 0, $this->getConf('oldpass'));		
    		return $passhistory;
    	} else {
    		return false;
    	}
    	
    }
    
    /**
     * returns the modification date of the passhistory file, which is the date when user changed password
     * @param string $user
     */
    protected function getPassHistoryChangeDate($user=false) {
    	if(!$user && $_SERVER['REMOTE_USER']) $user = $_SERVER['REMOTE_USER'];
    	
    	return @filemtime($this->passhistorydir . utf8_encodeFN($user) .'.txt');
    }
    
    /**
     * saves the given password to the passHistory file
     * 
     * @param string $user
     * @param string $pass
     */
    public function savePassword2PassHistory($user,$pass) {
    	$passhistory = $this->getUserPassHistory($user);
    	if(!$passhistory) {
    		$passhistory = auth_cryptPassword($pass);
    	} else {
    		array_unshift($passhistory, auth_cryptPassword($pass));
    		$passhistory = array_slice($passhistory, 0, $this->getConf('oldpass'));
    		$passhistory = implode("\n", $passhistory);
    	}

    	io_saveFile($this->passhistorydir .utf8_encodeFN($user).'.txt', $passhistory);
    }

}

/**
 * Class helper_plugin_passpolicy__index
 *
 * just to access a protected function
 */
class helper_plugin_passpolicy__index extends Doku_Indexer {
    public function getIndex($idx, $suffix) {
        return parent::getIndex($idx, $suffix);
    }
}

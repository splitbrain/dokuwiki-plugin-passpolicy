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

    const LENGTH_VIOLATION   = 1;
    const POOL_VIOLATION     = 2;
    const USERNAME_VIOLATION = 4;

    /**
     * Constructor
     *
     * Sets the policy from the DokuWiki config
     */
    public function __construct() {
        $this->min_length    = $this->getConf('minlen');
        $this->min_pools     = $this->getConf('minpools');
        $this->usernamecheck = $this->getConf('user');
        $this->autotype      = $this->getConf('autotype');
        $this->autobits      = $this->getConf('autobits');

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
     * @param $username
     * @return bool|string
     * @throws Exception when no password matching the current policy can be created
     */
    public function generatePassword($username) {
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

        // still here? we have big problem
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
            $text .= sprintf($this->getLang('length'), $this->min_length)."\n";
        if($this->min_pools)
            $text .= sprintf($this->getLang('pools'), $this->min_pools, join(', ', $pools))."\n";
        if($this->usernamecheck == 1)
            $text .= $this->getLang('user1')."\n";
        if($this->usernamecheck > 1)
            $text .= sprintf($this->getLang('user2'), $this->usernamecheck)."\n";

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
        if(strlen($pass) < $this->min_length) {
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
            $pass     = utf8_strtolower($pass);
            $username = utf8_strtolower($username);

            // simplest case first
            if(utf8_stripspecials($pass, '', '\._\-:\*') == utf8_stripspecials($username, '', '\._\-:\*')) {
                $this->error = helper_plugin_passpolicy::USERNAME_VIOLATION;
                return false;
            }

            // find possible chunks in the lenght defined in policy
            if($this->usernamecheck > 1) {
                $chunks = array();
                for($i = 0; $i < utf8_strlen($pass) - $this->usernamecheck + 1; $i++) {
                    $chunk = utf8_substr($pass, $i, $this->usernamecheck + 1);
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

        return true;
    }

    /**
     * Creates a completely random password
     *
     * @return string
     */
    protected function randomPassword() {
        $usablepools = array();
        $pw          = '';
        // make sure all char pools are used
        foreach($this->usepools as $pool => $on) {
            if($on) {
                $poollen = strlen($this->pools[$pool]);
                $pw .= $this->pools[$pool][$this->rand(0, $poollen - 1)];
                $usablepools[] = $pool;
            }
        }
        if(!$usablepools) return false;

        // now fill up
        $poolcnt = count($usablepools);
        for($i = strlen($pw); $i < $this->min_length; $i++) {
            $pool = $this->pools[$usablepools[$this->rand(0, $poolcnt - 1)]];
            $pw .= $pool[$this->rand(0, strlen($pool) - 1)];
        }

        // shuffle to make sure our intial chars are not necessarily at the start
        return str_shuffle($pw);
    }

    /**
     * Creates a pronouncable password
     *
     * @return bool|string  the new password, false on error
     */
    protected function pronouncablePassword() {
        // prepare speakable char classes
        $consonants = 'bcdfghjklmnprstvwz'; //consonants except hard to speak ones
        $first      = $consonants;
        if(empty($this->usepools['lower'])) $consonants = strtoupper($consonants);
        if(!empty($this->usepools['upper'])) $first = strtoupper($consonants); // prefer upper for first syllable letter
        $vowels   = 'aeiou';
        $all      = $consonants.$vowels;
        $specials = '!$%&=?.-_;,';

        // calculate syllable number
        $len = $this->min_length + 1;
        if(!empty($this->usepools['numeric'])) $len -= 2; // we add two numbers later
        if(!empty($this->usepools['special'])) $len -= 1; // we add one special later
        $syllables = ceil($len / 3);

        // create words
        $pw = '';
        for($i = 0; $i < $syllables; $i++) {
            $pw .= $first[$this->rand(0, strlen($first) - 1)];
            $pw .= $vowels[$this->rand(0, strlen($vowels) - 1)];
            $pw .= $all[$this->rand(0, strlen($all) - 1)];
        }

        // add a nice numbers and specials
        if(!empty($this->usepools['numeric'])) $pw .= $this->rand(10, 99);
        if(!empty($this->usepools['special'])) $pw .= $specials[$this->rand(0, strlen($specials) - 1)];

        return $pw;
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
        if(!function_exists('openssl_random_pseudo_bytes')) {
            return mt_rand($min, $max);
        }

        $real_max = $max - $min;
        $mask     = (1 << $this->bits($real_max)) - 1;

        do {
            $bytes = openssl_random_pseudo_bytes(4, $strong);
            assert($strong);
            $integer = unpack("lnum", $bytes)["num"] & $mask;
        } while($integer > $real_max);

        return $integer + $min;
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
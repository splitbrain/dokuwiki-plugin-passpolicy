<?php
/**
 * @group plugin_passpolicy
 * @group plugins
 */
class helper_plugin_passpolicy_test extends DokuWikiTest {

    protected $pluginsEnabled = array('passpolicy');

    /**
     * 
     * @param int $minl
     * @param int $minp
     * @param boolean $lower
     * @param boolean $upper
     * @param boolean $num
     * @param boolean $special
     * @param boolean $ucheck
     * @param boolean $pron
     * @param int $oldpass
     * @param int $expire_days
     * @param int $expirewarn_days
     * @param string $data_start date YYYY-MM-DD
     * @return helper_plugin_passpolicy
     */
    public function newPolicy($minl, $minp, $lower, $upper, $num, $special, $ucheck, $pron=true,$oldpass=0,$date_start='2030-01-01',$expire_days=0,$expirewarn_days=2) {
        /* @var $policy helper_plugin_passpolicy */
        $policy                = plugin_load('helper', 'passpolicy');
        $policy->min_pools     = $minp;
        $policy->min_length    = $minl;
        $policy->usepools      = array(
            'lower'   => $lower,
            'upper'   => $upper,
            'numeric' => $num,
            'special' => $special
        );
        $policy->usernamecheck = $ucheck;
        $policy->pronouncable  = $pron;
        
        $policy->oldpass             = $oldpass;
        $policy->conf['oldpass']     = $oldpass;
        $policy->conf['expire']      = $expire_days;
        $policy->conf['expirewarn']  = $expirewarn_days;
        $policy->conf['date_start']  = $date_start;

        return $policy;
    }
    
    public function changePass($pass,$user = 'testuser') {
        global $auth;
        
        return $auth->triggerUserMod('modify',array(
            $user,
            array('pass'=>$pass)
        ));
    }

    public function test_policies() {
        $policy = $this->newPolicy(6, 1, true, true, true, true, 0);
        $this->assertTrue($policy->checkPolicy('tested','tested'), '1 pool, no user check '.$policy->error);
        $this->assertFalse($policy->checkPolicy('test','tested'), '1 pool, no user check, but too short '.$policy->error);
        $this->assertEquals(helper_plugin_passpolicy::LENGTH_VIOLATION, $policy->error);
        $this->assertTrue($policy->checkPolicy('tested99!','tested'), '1 pool, no user check '.$policy->error);

        $policy = $this->newPolicy(6, 3, true, true, true, true, 0);
        $this->assertFalse($policy->checkPolicy('tested','tested'), '3 pools, no user check '.$policy->error);
        $this->assertEquals(helper_plugin_passpolicy::POOL_VIOLATION, $policy->error);
        $this->assertTrue($policy->checkPolicy('tested99!','tested'), '3 pools, no user check '.$policy->error);

        $policy = $this->newPolicy(6, 1, true, true, true, true, 2);
        $this->assertFalse($policy->checkPolicy('tested','tested'), '1 pool, user check '.$policy->error);
        $this->assertEquals(helper_plugin_passpolicy::USERNAME_VIOLATION, $policy->error);
        $this->assertFalse($policy->checkPolicy('tested99!','tested'), '1 pool, user check '.$policy->error);
        $this->assertEquals(helper_plugin_passpolicy::USERNAME_VIOLATION, $policy->error);
        $this->assertFalse($policy->checkPolicy('tested','untested'), '1 pool, user check '.$policy->error);
        $this->assertEquals(helper_plugin_passpolicy::USERNAME_VIOLATION, $policy->error);
        $this->assertFalse($policy->checkPolicy('tested99!','comptessa'), '1 pool1, user check '.$policy->error);
        $this->assertEquals(helper_plugin_passpolicy::USERNAME_VIOLATION, $policy->error);
    }

    public function test_minpools(){
        $policy = $this->newPolicy(3, 0, true, true, true, true, 0);
        $this->assertTrue($policy->checkPolicy('lowerUPPER123!"','tester'), '0 required, 4 given '.$policy->error);
        $this->assertTrue($policy->checkPolicy('lowerUPPER123','tester'), '0 required, 3 given '.$policy->error);
        $this->assertTrue($policy->checkPolicy('lowerUPPER','tester'), '0 required, 2 given '.$policy->error);
        $this->assertTrue($policy->checkPolicy('lower','tester'), '0 required, 1 given '.$policy->error);

        $policy = $this->newPolicy(3, 1, true, true, true, true, 0);
        $this->assertTrue($policy->checkPolicy('lowerUPPER123!"','tester'), '1 required, 4 given '.$policy->error);
        $this->assertTrue($policy->checkPolicy('lowerUPPER123','tester'), '1 required, 3 given '.$policy->error);
        $this->assertTrue($policy->checkPolicy('lowerUPPER','tester'), '1 required, 2 given '.$policy->error);
        $this->assertTrue($policy->checkPolicy('lower','tester'), '1 required, 1 given '.$policy->error);

        $policy = $this->newPolicy(3, 2, true, true, true, true, 0);
        $this->assertTrue($policy->checkPolicy('lowerUPPER123!"','tester'), '2 required, 4 given '.$policy->error);
        $this->assertTrue($policy->checkPolicy('lowerUPPER123','tester'), '2 required, 3 given '.$policy->error);
        $this->assertTrue($policy->checkPolicy('lowerUPPER','tester'), '2 required, 2 given '.$policy->error);
        $this->assertFalse($policy->checkPolicy('lower','tester'), '2 required, 1 given '.$policy->error);
        $this->assertEquals(helper_plugin_passpolicy::POOL_VIOLATION, $policy->error);

        $policy = $this->newPolicy(3, 3, true, true, true, true, 0);
        $this->assertTrue($policy->checkPolicy('lowerUPPER123!"','tester'), '3 required, 4 given '.$policy->error);
        $this->assertTrue($policy->checkPolicy('lowerUPPER123','tester'), '3 required, 3 given '.$policy->error);
        $this->assertFalse($policy->checkPolicy('lowerUPPER','tester'), '3 required, 2 given '.$policy->error);
        $this->assertEquals(helper_plugin_passpolicy::POOL_VIOLATION, $policy->error);
        $this->assertFalse($policy->checkPolicy('lower','tester'), '3 required, 1 given '.$policy->error);
        $this->assertEquals(helper_plugin_passpolicy::POOL_VIOLATION, $policy->error);

        $policy = $this->newPolicy(3, 4, true, true, true, true, 0);
        $this->assertTrue($policy->checkPolicy('lowerUPPER123!"','tester'), '4 required, 4 given '.$policy->error);
        $this->assertFalse($policy->checkPolicy('lowerUPPER123','tester'), '4 required, 3 given '.$policy->error);
        $this->assertEquals(helper_plugin_passpolicy::POOL_VIOLATION, $policy->error);
        $this->assertFalse($policy->checkPolicy('lowerUPPER','tester'), '4 required, 2 given '.$policy->error);
        $this->assertEquals(helper_plugin_passpolicy::POOL_VIOLATION, $policy->error);
        $this->assertFalse($policy->checkPolicy('lower','tester'), '4 required, 1 given '.$policy->error);
        $this->assertEquals(helper_plugin_passpolicy::POOL_VIOLATION, $policy->error);
    }

    public function test_selfcheck() {
        $policy = $this->newPolicy(6, 4, true, true, true, true, 0, true);
        $pw1 = $policy->generatePassword('test');
        $pw2 = $policy->generatePassword('test');
        $this->assertNotEquals($pw1, $pw2, 'randomness broken');
        $this->assertTrue(strlen($pw1) >= 6, 'pw too short');
        $this->assertTrue(strlen($pw2) >= 6, 'pw too short');
        $this->assertTrue(utf8_isASCII($pw1), 'pw contains non-ASCII, something went wrong');
        $this->assertTrue(utf8_isASCII($pw2), 'pw contains non-ASCII, something went wrong');

        //echo "\n$pw1\n$pw2\n";

        $policy = $this->newPolicy(18, 4, true, true, true, true, 0, true);
        $pw1 = $policy->generatePassword('test');
        $pw2 = $policy->generatePassword('test');
        $this->assertNotEquals($pw1, $pw2, 'randomness broken');
        $this->assertTrue(strlen($pw1) >= 18, 'pw too short');
        $this->assertTrue(strlen($pw2) >= 18, 'pw too short');
        $this->assertTrue(utf8_isASCII($pw1), 'pw contains non-ASCII, something went wrong');
        $this->assertTrue(utf8_isASCII($pw2), 'pw contains non-ASCII, something went wrong');

        //echo "\n$pw1\n$pw2\n";

        $policy = $this->newPolicy(6, 4, true, true, true, true, 0, false);
        $pw1 = $policy->generatePassword('test');
        $pw2 = $policy->generatePassword('test');
        $this->assertNotEquals($pw1, $pw2, 'randomness broken');
        $this->assertTrue(strlen($pw1) >= 6, 'pw too short');
        $this->assertTrue(strlen($pw2) >= 6, 'pw too short');
        $this->assertTrue(utf8_isASCII($pw1), 'pw contains non-ASCII, something went wrong');
        $this->assertTrue(utf8_isASCII($pw2), 'pw contains non-ASCII, something went wrong');

        //echo "\n$pw1\n$pw2\n";

        $policy = $this->newPolicy(18, 4, true, true, true, true, 0, false);
        $pw1 = $policy->generatePassword('test');
        $pw2 = $policy->generatePassword('test');
        $this->assertNotEquals($pw1, $pw2, 'randomness broken');
        $this->assertTrue(strlen($pw1) >= 18, 'pw too short');
        $this->assertTrue(strlen($pw2) >= 18, 'pw too short');
        $this->assertTrue(utf8_isASCII($pw1), 'pw contains non-ASCII, something went wrong');
        $this->assertTrue(utf8_isASCII($pw2), 'pw contains non-ASCII, something went wrong');

        //echo "\n$pw1\n$pw2\n";

        $policy = $this->newPolicy(18, 1, false, false, false, true, 0, false);
        $pw1 = $policy->generatePassword('test');
        $pw2 = $policy->generatePassword('test');
        $this->assertNotEquals($pw1, $pw2, 'randomness broken');
        $this->assertTrue(strlen($pw1) >= 18, 'pw too short');
        $this->assertTrue(strlen($pw2) >= 18, 'pw too short');
        $this->assertTrue(utf8_isASCII($pw1), 'pw contains non-ASCII, something went wrong');
        $this->assertTrue(utf8_isASCII($pw2), 'pw contains non-ASCII, something went wrong');

        //echo "\n$pw1\n$pw2\n";

        $policy = $this->newPolicy(18, 1, false, false, true, false, 0, false);
        $pw1 = $policy->generatePassword('test');
        $pw2 = $policy->generatePassword('test');
        $this->assertNotEquals($pw1, $pw2, 'randomness broken');
        $this->assertTrue(strlen($pw1) >= 18, 'pw too short');
        $this->assertTrue(strlen($pw2) >= 18, 'pw too short');
        $this->assertTrue(utf8_isASCII($pw1), 'pw contains non-ASCII, something went wrong');
        $this->assertTrue(utf8_isASCII($pw2), 'pw contains non-ASCII, something went wrong');

        //echo "\n$pw1\n$pw2\n";

        $policy = $this->newPolicy(18, 1, false, true, false, false, 0, false);
        $pw1 = $policy->generatePassword('test');
        $pw2 = $policy->generatePassword('test');
        $this->assertNotEquals($pw1, $pw2, 'randomness broken');
        $this->assertTrue(strlen($pw1) >= 18, 'pw too short');
        $this->assertTrue(strlen($pw2) >= 18, 'pw too short');
        $this->assertTrue(utf8_isASCII($pw1), 'pw contains non-ASCII, something went wrong');
        $this->assertTrue(utf8_isASCII($pw2), 'pw contains non-ASCII, something went wrong');

        //echo "\n$pw1\n$pw2\n";

        $policy = $this->newPolicy(18, 1, true, false, false, false, 0, false);
        $pw1 = $policy->generatePassword('test');
        $pw2 = $policy->generatePassword('test');
        $this->assertNotEquals($pw1, $pw2, 'randomness broken');
        $this->assertTrue(strlen($pw1) >= 18, 'pw too short');
        $this->assertTrue(strlen($pw2) >= 18, 'pw too short');
        $this->assertTrue(utf8_isASCII($pw1), 'pw contains non-ASCII, something went wrong');
        $this->assertTrue(utf8_isASCII($pw2), 'pw contains non-ASCII, something went wrong');

        //echo "\n$pw1\n$pw2\n";
    }
    
    public function test_passhistory() {
        
        $policy = $this->newPolicy(6, 4, true, true, true, true, 0, true,2);
        $pw1 = $policy->generatePassword('testuser');
        $pw2 = $policy->generatePassword('testuser');
        $pw3 = $policy->generatePassword('testuser');
        
        $this->assertTrue($this->changePass($pw1),'cannot change password');
        $this->assertNull($this->changePass($pw1),'last password can be used');
        $this->assertTrue($this->changePass($pw2),'cannot change password');
        $this->assertNull($this->changePass($pw1),'second last password can be used');
        $this->assertTrue($this->changePass($pw3),'cannot change password');
        $this->assertTrue($this->changePass($pw1),'third last password can be used');
        $this->assertNull($this->changePass($pw3),'second last password can be used');
        
        //$policy = $this->newPolicy(18, 1, true, false, false, false, 0, false,0,0,2,date('Y-m-d',time()+3600*2));
        
    }
    
    public function test_pass_expire() {
        $policy = $this->newPolicy(6, 4, true, true, true, true, 0, true,
            0, //oldpass
            '2010-01-01', //$date_start
            2,//expire_days=0
            0//expirewarn_days
        );

        $userFile = $policy->passhistorydir  .'testuser.txt';
        
        TestUtils::rdelete($userFile);
        $this->assertEquals(strtotime($policy->getConf('date_start')),$policy->checkPasswordExpired('testuser'));
        $this->assertFalse($policy->checkPasswordExpireWarn('testuser'));
        
        touch($userFile,time());
        $this->assertFalse($policy->checkPasswordExpired('testuser'));
        $this->assertFalse($policy->checkPasswordExpireWarn('testuser'));
        TestUtils::rdelete($userFile);

        $changedTime = time() - 3600*48-1;
        touch($userFile,$changedTime);
        $this->assertEquals($changedTime+3600*48,$policy->checkPasswordExpired('testuser'),'password is not expired');
        $this->assertFalse($policy->checkPasswordExpireWarn('testuser'));
        
    }
    
    public function test_pass_expire_warn() {
        $policy = $this->newPolicy(6, 4, true, true, true, true, 0, true,
            0, //oldpass
            '2010-01-01', //$date_start
            14,//expire_days=0
            2//expirewarn_days
        );
    
        $userFile = $policy->passhistorydir  .'testuser.txt';
    
        TestUtils::rdelete($userFile);
        $this->assertEquals(strtotime($policy->getConf('date_start')),$policy->checkPasswordExpireWarn('testuser'));
    
        touch($userFile,time());
        $this->assertFalse($policy->checkPasswordExpired('testuser'));
        $this->assertFalse($policy->checkPasswordExpireWarn('testuser'));
        TestUtils::rdelete($userFile);
    
        $changedTime = time() - 3600*24*12-1;
        touch($userFile,$changedTime);
        $this->assertFalse($policy->checkPasswordExpired('testuser'));
        $this->assertEquals($changedTime+3600*24*14,$policy->checkPasswordExpireWarn('testuser'),'we have to warn!');
    
    }
    
    public function test_pass_date_start() {
        $policy = $this->newPolicy(6, 4, true, true, true, true, 0, true,
            0, //oldpass
            date('Y-m-d',time()+3600*24*5), //$date_start
            2,//expire_days=0
            6//expirewarn_days
        );
        
        $userFile = $policy->passhistorydir  .'testuser.txt';
        TestUtils::rdelete($userFile);
        
        $this->assertEquals(strtotime($policy->getConf('date_start')),$policy->checkPasswordExpireWarn('testuser'),'we have to warn!');
        $this->assertFalse($policy->checkPasswordExpired('testuser'),'date start is in future');
        
        $policy = $this->newPolicy(6, 4, true, true, true, true, 0, true,
            0, //oldpass
            date('Y-m-d',time()+3600*24*5), //$date_start
            2,//expire_days=0
            4//expirewarn_days
        );
        
        $userFile = $policy->passhistorydir  .'testuser.txt';
        
        $this->assertFalse($policy->checkPasswordExpireWarn('testuser'),'its not time to warn');
        $this->assertFalse($policy->checkPasswordExpired('testuser'),'date start is in future');
        
    }
}


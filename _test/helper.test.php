<?php
/**
 * @group plugin_passpolicy
 * @group plugins
 */
class helper_plugin_passpolicy_test extends DokuWikiTest {

    protected $pluginsEnabled = array('passpolicy');

    /**
     * Quickly create a custom policy
     *
     * @param int     $minl
     * @param int     $minp
     * @param boolean $lower
     * @param boolean $upper
     * @param boolean $num
     * @param boolean $special
     * @param boolean $ucheck
     * @param boolean $pron
     * @param bool    $nocom
     * @return helper_plugin_passpolicy
     */
    public function newPolicy($minl, $minp, $lower, $upper, $num, $special, $ucheck, $pron=true, $nocom=true) {
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
        $policy->pronouncable = $pron;
        $policy->nocommon = true;

        return $policy;
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

    public function test_nocommon(){
        $policy = $this->newPolicy(6, 1, true, true, true, true, 0, true, true);
        $this->assertTrue($policy->checkPolicy('bazzel', 'nope'));
        $this->assertFalse($policy->checkPolicy('eyphed', 'nope'));
        $this->assertEquals(helper_plugin_passpolicy::COMMON_VIOLATION, $policy->error);

        $policy->nocommon = false;
        $this->assertTrue($policy->checkPolicy('password', 'nope'));
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
}


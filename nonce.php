<?php

session_start();

////////////////////TESTINGFUNCTIONS////////////////////////

function test($name,$result) {
  global $expected;
  global $actual;

  $results = makeresult($result);
  echo "<table><tr><td colspan=2>{$name}: <b>{$results}</b></td></tr><tr><td width=50>Expected:</td><td>".htmlentities($expected)."</td><tr><td>Actual:</td><td>".htmlentities($actual)."</td><hr/>";
}
function makeresult($result) {
  if ($result === true) return "<font color=\"green\">Passed</font><br/>";
  else if ($result === false) return "<font color=\"red\">Failed</font><br/>";
  else return "<font color=\"purple\">No Result</font><br/>";
}

function setexpected($exp) {
  global $expected;
  $expected = null;
  $expected = $exp;
  return $expected;
}

function setactual($act,$with_output = false) {
  global $actual;
  if ($with_output === true) file_put_contents("./output.html",$act);
  $actual = null;
  $actual = $act;
  return $actual;
}

function build($text,$newtext) {
  return $text . $newtext . " ";
}

echo "<font face=\"Verdana\"><p>Testing Is Running:</p>";

////////////////////END TESTINGFUNCTIONS////////////////////////

////////////////////code under test/////////////////////////////
interface nonce_generator
{
	public function generate_nonce($token);
}

interface nonce_repository
{
	public function save_nonce($nonce_name, $token);
	public function check_nonce($nonce_name, $nonce_value);
	public function clear_specific_nonce($nonce_name);
	public function clear_all_nonces();
}

class microtime_based_nonce_generator implements nonce_generator
{
	public function generate_nonce($token)
	{
		//echo "<h3>microtime().".$token.";</h3>";
		return microtime().$token;
	}
}

class md5_based_nonce_generator implements nonce_generator
{
	public function __construct(nonce_generator $pre_handler = null)
	{
		if (is_null($pre_handler))
		{
			throw new Exception("nonce handler is required");
		}
		$this->_pre_handler = $pre_handler;
	}

	private $_pre_handler;
	public function pre_handler()
	{
		return $this->_pre_handler;
	}

	public function generate_nonce($token)
	{
		//echo "<h3>hash(\"md5\", \$this->_pre_handler->generate_nonce(".$token."));</h3>";
		return hash("md5", $this->_pre_handler->generate_nonce($token));
	}
}

class sha256_based_nonce_generator implements nonce_generator
{
	public function __construct(nonce_generator $pre_handler = null)
	{
		if (is_null($pre_handler)) 
		{
			throw new Exception("nonce handler is required");
		}
		$this->_pre_handler = $pre_handler;
	}

	private $_pre_handler;
	public function pre_handler()
	{
		return $this->_pre_handler;
	}

	public function generate_nonce($token)
	{
		//echo "<h3>hash(\"sha256\", \$this->_pre_handler->generate_nonce(".$token."));</h3>";
		return hash("sha256", $this->_pre_handler->generate_nonce($token));
	}
}

class session_based_nonce_generator implements nonce_repository
{	
	public function __construct(nonce_generator $pre_handler = null, $store_name = "nonce")
	{
		if (is_null($store_name)) { throw new exception("store name cannot be null"); }
		if (is_null($pre_handler)) { throw new exception("handler cannot be null"); }
		$this->_store_name = $store_name;
		$_SESSION[$this->_store_name] = array();
		$this->_pre_handler = $pre_handler;
	}

	private $_store_name;
	public function store_name()
	{
		return $this->_store_name;
	}

	private $_pre_handler;
	public function pre_handler()
	{
		return $this->_pre_handler;
	}

	public function save_nonce($nonce_name,$token)
	{
		//echo "<h3>\$nonce_value = \$this->_pre_handler->generate_nonce(".$token.");</h3>";
		$nonce_value = $this->_pre_handler->generate_nonce($token);
		//echo "<h3>\$_SESSION[\$this->_store_name][\$nonce_name] = ".$nonce_value.";</h3>";
		$_SESSION[$this->_store_name][$nonce_name] = $nonce_value;
		return($nonce_value);
	}

	public function check_nonce($nonce_name, $nonce_value)
	{
		$returnval = false;
		$previous = error_reporting();
		error_reporting("E_NONE");
		try {
			if (!array_key_exists($this->_store_name, $_SESSION)) throw new Exception("session store was ruined");
			if ($_SESSION[$this->_store_name][$nonce_name] === $nonce_value) $returnval = true;			
		} catch (Exception $e) {
			throw $e;
		}
		
		$this->clear_specific_nonce($nonce_name);
		error_reporting($previous);

		return $returnval;
	}

	public function clear_specific_nonce($nonce_name)
	{
		unset($_SESSION[$this->_store_name][$nonce_name]);
	}

	public function clear_all_nonces()
	{
		$_SESSION[$this->_store_name] = array();
	}
}
////////////////////end code under test/////////////////////////

////////////////////test list///////////////////////////////////

class dummy_handler_for_testing extends microtime_based_nonce_generator
{
	private $wascalled = false;
	public function generate_nonce($token)
	{
		$this->wascalled = true;
		return $token;
	}
	public function get_was_called()
	{
		return $this->wascalled;
	}
}

function testframework() 
{
  $expected = setexpected("test framework is functional");
  $actual = setactual("test framework is functional");
  return ($expected === $actual);
}
test("TestFrameworkIsFunctional",call_user_func('testframework'));

function testsha256inherit()
{
	$expected = setexpected(true);
	
	$sut = new sha256_based_nonce_generator(new microtime_based_nonce_generator());
	
	$actual = setactual(is_a($sut,nonce_generator));
	return ($expected === $actual);
}
test("SHA256HandlerIsANonceHandler",call_user_func(testsha256inherit));

function testmd5inherit()
{
	$expected = setexpected(true);
	
	$sut = new md5_based_nonce_generator(new microtime_based_nonce_generator());
	
	$actual = setactual(is_a($sut,nonce_generator));
	return ($expected === $actual);
}
test("MD5HandlerIsANonceHandler",call_user_func(testmd5inherit));

function testhandlerinherit()
{
	$expected = setexpected(true);
	
	$sut = new session_based_nonce_generator(new dummy_handler_for_testing());
	
	$actual = setactual(is_a($sut, nonce_repository));
	return ($expected === $actual);
}
test("SessionBasedNonceHandlerIsNonceRepository",call_user_func(testhandlerinherit));

function testnullsessionnamethrows()
{
	$expected = setexpected("exception was thrown");
	try {
		$sut = new session_based_nonce_generator(null);
		$actual = setactual("exception was not thrown");
	} catch (Exception $e) {
		$actual = setactual("exception was thrown");
	}	
	return ($expected === $actual);
}
test("NullSessionNameThrows",call_user_func(testnullsessionnamethrows));

function testdefaultnameforstore()
{
	$expected = setexpected("nonce");
	
	$sut = new session_based_nonce_generator(new sha256_based_nonce_generator(new microtime_based_nonce_generator()));
	
	$actual = setactual($sut->store_name());
	return ($expected === $actual);
}
test("DefaultNameForStoreIsCorrect",call_user_func(testdefaultnameforstore));

function testsuppliednameforstore()
{
	$expected = setexpected("suppliedName");
	
	$sut = new session_based_nonce_generator(new sha256_based_nonce_generator(new microtime_based_nonce_generator()), $expected);
	
	$actual = setactual($sut->store_name());
	return $expected === $actual;
}
test("SuppliedNameForStoreIsCorrect",call_user_func(testsuppliednameforstore));

function testrequiredhandlernullthrows()
{
	$expected = setexpected("exception was thrown");
	try {
		$sut = new session_based_nonce_generator(null);
		$actual = setactual("exception was not thrown");
	} catch (Exception $e) {
		$actual = setactual("exception was thrown");
	}
	return ($expected === $actual);
}
test("RequiredHandlerThrowsWhenNull",call_user_func(testrequiredhandlernullthrows));

function timebasednonceisnoncehandler() 
{
	$expected = setexpected(true);
	
	$sut = new microtime_based_nonce_generator();
	
	$actual = setactual(is_a($sut, nonce_generator));
	return($expected === $actual);
}
test("TimeBasedNonceIsANonceHandler",call_user_func(timebasednonceisnoncehandler));

function sha256noncehandlercannotbenull()
{
	$expected = setexpected("exception was thrown");
	try {
		$sut = new sha256_based_nonce_generator(null);
		$actual = setactual("exception was not thrown");
	} catch (Exception $e) {
		$actual = setactual("exception was thrown");
	}
	return ($expected === $actual);
}
test("SHA256NullNonceHandlerThrows",call_user_func(sha256noncehandlercannotbenull));

function md5noncehandlercannotbenull()
{
	$expected = setexpected("exception was thrown");
	try {
		$sut = new md5_based_nonce_generator(null);
		$actual = setactual("exception was not thrown");
	} catch (Exception $e) {
		$actual = setactual("exception was thrown");
	}
	return ($expected === $actual);
}
test("MD5NullNonceHandlerThrows",call_user_func(md5noncehandlercannotbenull));

function dummyhandlerreturnssupplied()
{
	$value = "UNIQUEsomeExpectedValue";
	$expected = setexpected($value);
	
	$sut = new dummy_handler_for_testing();
	
	$actual = setactual($sut->generate_nonce($value));
	return ($expected === $actual);
}
test("ValueForDummyTimeTestingCannotReturnNull",call_user_func(dummyhandlerreturnssupplied));

function verifyconstanttimevaluefortestingisconsecutivelysame()
{	
	$sut = new dummy_handler_for_testing();
	$expected = setexpected($sut->generate_nonce(null));	
	$actual = setactual($sut->generate_nonce(null));
	return ($expected === $actual);
}
test("TwoConsecutiveCallsToTimeBasedNonceForTestingAreSame",call_user_func(verifyconstanttimevaluefortestingisconsecutivelysame));

function verifynotconstanttimevaluefortesting() 
{	
	$sut = new microtime_based_nonce_generator();

	$expected = setexpected($sut->generate_nonce(null));
	
	$actual = setactual($sut->generate_nonce(null));
	return($expected !== $actual);
}
test("TwoConsecutiveCallsToTimeBasedNonceForProductionAreNotSame",call_user_func(verifynotconstanttimevaluefortesting));

function suppliedtokenappendedtotime()
{
	$searchValue = "someBogusToken";
	$expected = setexpected(1);
	
	$sut = new microtime_based_nonce_generator();
	
	$actual = setactual(substr_count($sut->generate_nonce($searchValue),$searchValue));
	return($expected === $actual);
}
test("SuppliedTokenAppendedToTimeToken",call_user_func(suppliedtokenappendedtotime));

function testgeneratesha256nonceusingdummyhandler()
{
	$dummyhandler = new dummy_handler_for_testing();
	$dummysalt = 'someSaltForHash';
	$expected = setexpected(hash("sha256",$dummysalt));
	
	$sut = new sha256_based_nonce_generator($dummyhandler);
	
	$actual = setactual($sut->generate_nonce($dummysalt));
	return ($expected === $actual);
}
test("GenerateSha256BasedNonceReturnsExpectedUsingDummyHandler",call_user_func(testgeneratesha256nonceusingdummyhandler));

function sha256setsprehandler() 
{
	$subject = new dummy_handler_for_testing();
	$expected = setexpected(true);
	
	$sut = new sha256_based_nonce_generator($subject);
	
	$actual = setactual(($subject === $sut->pre_handler()));
	return($expected === $actual);
}
test("SHA256HandlerSetsPreHandlerCorrectly",call_user_func(sha256setsprehandler));

function testgeneratesha256nonceusingmicrotimehandler()
{
	$dummyname = "someNonceName";
	$testsalt = "someSaltForHash";
	$expected = setexpected(hash("sha256",$testsalt));
	
	$sut = new sha256_based_nonce_generator(new microtime_based_nonce_generator());
	
	$actual = setactual($sut->generate_nonce($testsalt));
	return ($expected !== $actual);
}
test("GenerateSha256BasedNonceReturnsExpectedUsingMicroTimeHandler",call_user_func(testgeneratesha256nonceusingmicrotimehandler));

function twosaltvaluesyeilddifferenthashes()
{
	$testsalt1 = "somesalt1";
	$testsalt2 = "somesalt2";
	$expected = setexpected(false);
	
	$sut = new sha256_based_nonce_generator(new dummy_handler_for_testing());
	$token1 = $sut->generate_nonce($testsalt1);
	$token2 = $sut->generate_nonce($testsalt2);	
	
	$actual = setactual(($token1 == $token2));
	return($expected === $actual);
}
test("TwoSaltValuesWhenHashedUsingDummyHandlerAreNotSame",call_user_func(twosaltvaluesyeilddifferenthashes));

function testgeneratemd5nonceusingdummyhandler()
{
	$dummyhandler = new dummy_handler_for_testing();
	$dummysalt = 'someSaltForHash';
	$expected = setexpected(hash("md5",$dummysalt));
	
	$sut = new md5_based_nonce_generator($dummyhandler);
	
	$actual = setactual($sut->generate_nonce($dummysalt));
	return ($expected === $actual);
}
test("GenerateMd5BasedNonceReturnsExpectedUsingDummyHandler",call_user_func(testgeneratemd5nonceusingdummyhandler));

function md5setsprehandler() 
{
	$subject = new dummy_handler_for_testing();
	$expected = setexpected(true);
	
	$sut = new md5_based_nonce_generator($subject);
	
	$actual = setactual(($subject === $sut->pre_handler()));
	return($expected === $actual);
}
test("MD5HandlerSetsPreHandlerCorrectly",call_user_func(md5setsprehandler));

function testgeneratemd5nonceusingmicrotimehandler()
{
	$dummyname = "someNonceName";
	$testsalt = "someSaltForHash";
	$expected = setexpected(hash("md5",$testsalt));
	
	$sut = new md5_based_nonce_generator(new microtime_based_nonce_generator());
	
	$actual = setactual($sut->generate_nonce($testsalt));
	return ($expected !== $actual);
}
test("GenerateMd5BasedNonceReturnsExpectedUsingMicroTimeHandler",call_user_func(testgeneratemd5nonceusingmicrotimehandler));

function twosaltvaluesmd5yeilddifferenthashes()
{
	$testsalt1 = "somesalt1";
	$testsalt2 = "somesalt2";
	$expected = setexpected(false);
	
	$sut = new md5_based_nonce_generator(new dummy_handler_for_testing());
	$token1 = $sut->generate_nonce($testsalt1);
	$token2 = $sut->generate_nonce($testsalt2);	
	
	$actual = setactual(($token1 == $token2));
	return($expected === $actual);
}
test("TwoSaltValuesWhenmd5HashedUsingDummyHandlerAreNotSame",call_user_func(twosaltvaluesmd5yeilddifferenthashes));

function sessionbasedprehandleriscorrect()
{
	$subject = new dummy_handler_for_testing();
	$expected = setexpected(true);
	
	$sut = new session_based_nonce_generator($subject);
	
	$actual = setactual(($subject === $sut->pre_handler()));
	return($expected === $actual);
}
test("PrehandlerSetsCorrectlyForSessionBasedNonceGenerator",call_user_func(sessionbasedprehandleriscorrect));

function sessionbasedsavesname()
{
	$expected = setexpected(true);
	$searchValue = "expectedKeyName";
	
	$sut = new session_based_nonce_generator(new dummy_handler_for_testing(), "myStore");
	$sut->save_nonce($searchValue,"dummyValue");
	
	$actual = setactual(array_key_exists($searchValue,$_SESSION["myStore"]));
	return($expected === $actual);
}
test("SessionStoreNameIsFoundInSessionAfterNonceSave",call_user_func(sessionbasedsavesname));

function sessionbasedsavesvalue()
{
	$expected = setexpected("expectedToken");
	
	$sut = new session_based_nonce_generator(new dummy_handler_for_testing(), "testStore");
	$sut->save_nonce("dummyName",$expected);
	
	$actual = setactual($_SESSION["testStore"]["dummyName"]);
	return ($expected === $actual);
}
test("SessionStoreValueIsFoundInSessionInCorrectLocationAfterSave",call_user_func(sessionbasedsavesvalue));

function noncecheckfindsvalue()
{
	$expected = setexpected(true);
	
	$sut = new session_based_nonce_generator(new dummy_handler_for_testing(), "flintyStore");
	$sut->save_nonce("checkhere","myValue");
	
	$actual = setactual($sut->check_nonce("checkhere","myValue"));
	return ($expected === $actual);
}
test("SessionBasedCheckNonceCanFindCorrectNonce",call_user_func(noncecheckfindsvalue));

function checkagainstnoexistreturnsfalse()
{
	$expected = setexpected(false);
	
	$sut = new session_based_nonce_generator(new dummy_handler_for_testing(), "aNewStore");
	$sut->save_nonce("donotcheckhere","myValue");
	
	$actual = setactual($sut->check_nonce("checkingsomewhereelse","myValue"));
	return ($expected === $actual);
}
test("SessionBasedCheckNonceReturnsFalseWhenArrayPositionNotExists",call_user_func(checkagainstnoexistreturnsfalse));

function checkagainstdestroyedsessionthrows()
{
	$expected = setexpected("an exception was thrown");

	$sut = new session_based_nonce_generator(new dummy_handler_for_testing(), "someStore");
	$sut->save_nonce("checkhere","myValue");

	$_SESSION = null;
	try {
		$sut->check_nonce("checkhere","myValue");
		$actual = setactual("an exception was not thrown");
	} catch (Exception $e) {
		$actual = setactual("an exception was thrown");
	}
	return ($expected === $actual);
}
test("SessionBasedCheckThrowsExceptionIfSessionWasRuinedSomehow",call_user_func(checkagainstdestroyedsessionthrows));

function clearspecificnonceworks()
{
	$sut = new session_based_nonce_generator(new dummy_handler_for_testing(), "someStore");
	$expected = setexpected(false);

	$sut->save_nonce("noncename","noncevalue");
	$sut->clear_specific_nonce("noncename");

	$actual = setactual($sut->check_nonce("noncename","noncevalue"));
	return ($expected === $actual);
}
test("NonceIsNotFoundAfterClear",call_user_func(clearspecificnonceworks));

function doublecheckreturnsfalse()
{
	$noncename = "checkme";
	$noncevalue = "avalue";
	$expected = setexpected(false);
	
	$sut = new session_based_nonce_generator(new dummy_handler_for_testing());
	$sut->save_nonce($noncename,$noncevalue);
	$sut->check_nonce($noncename,$noncevalue);

	$actual = setactual($sut->check_nonce($noncename,$noncevalue));
	return ($expected === $actual);
}
test("DoubleCheckNonceReturnsFalse",call_user_func(doublecheckreturnsfalse));

function clearallnounces()
{
	$nonce1 = "check1";
	$nonce2 = "check2";
	$value = "dummyValue";
	$expected = 0;

	$sut = new session_based_nonce_generator(new dummy_handler_for_testing());
	$sut->save_nonce($nonce1,$value);
	$sut->save_nonce($nonce2,$value);
	$sut->clear_all_nonces();

	$actual = setactual(count($_SESSION["nonce"]));
	return($expected === $actual);
}
test("ClearAllNouncesResetsStoreToEmptyArray",call_user_func(clearallnounces));

function sessionbasedsavecallsgenerateonprehandler()
{
	$noncename = "thisnonce";
	$salt = "somesaltForNonce";
	$expected = setexpected(true);
	$pre_handler = new dummy_handler_for_testing();
	
	$sut = new session_based_nonce_generator($pre_handler);
	$sut->save_nonce($noncename,$salt);
	
	$actual = setactual($pre_handler->get_was_called());
	return($expected === $actual);
}
test("GenerateNonceIsCalledOnSessionBasedSaveCommand",call_user_func(sessionbasedsavecallsgenerateonprehandler));

function sessionbasedsavereturnsexpected()
{
	$noncename = "anew nonce with spaces";
	$salt = "this is a test value";
	$expected = setexpected($salt);
	$pre_handler = new dummy_handler_for_testing();

	$sut = new session_based_nonce_generator($pre_handler);
	
	$actual = setactual($sut->save_nonce($noncename,$salt));
	return($expected === $actual);
}
test("SaveNonceReturnsExpectedValueFromGenerator",call_user_func(sessionbasedsavereturnsexpected));

function sessionbasedsavesavesinsessionexpected()
{
	$noncename = "testnoncename";
	$findvalue = "thisisAnotherFindValue";
	$expected = setexpected($findvalue);
	$pre_handler = new dummy_handler_for_testing();

	$sut = new session_based_nonce_generator($pre_handler);
	$sut->save_nonce($noncename,$findvalue);
	
	$actual = setactual($_SESSION["nonce"][$noncename]);
	return($expected === $actual);
}
test("SessionBasedNonceHandlerSavesValueFromGeneratorToSession",call_user_func(sessionbasedsavesavesinsessionexpected));

function sha256microtimefinalusage()
{
	$noncename = "myNonceName";
	$salt = "gobroncos";

	$microtime = new microtime_based_nonce_generator();
	$sha256microtime = new sha256_based_nonce_generator($microtime);
	$sut = new session_based_nonce_generator($sha256microtime,"myNonceStore");
	$expected = setexpected($sut->save_nonce($noncename,$salt));

	$actual = setactual($_SESSION["myNonceStore"][$noncename]);
	return($expected === $actual);
}
test("FinalUsagePatternForSha256MicroTime",call_user_func(sha256microtimefinalusage));

function md5sha256microtimefinalusage()
{
	$noncename = "myNonceName";
	$salt = "mySalt";
	$expected = setexpected(true);

	$microtime = new microtime_based_nonce_generator();
	$sha256microtime = new sha256_based_nonce_generator($microtime);
	$md5sha256microtime = new md5_based_nonce_generator($sha256microtime);
	$sut = new session_based_nonce_generator($md5sha256microtime);
	$nonce_value = $sut->save_nonce($noncename,$salt);

	$actual = setactual($sut->check_nonce($noncename, $nonce_value));
	return($expected === $actual);
}
test("FinalUsagePatterForComposePlusCheckMd5AndSha256",call_user_func(md5sha256microtimefinalusage));

////////////////////end test list///////////////////////////////

echo "</font>";

?>
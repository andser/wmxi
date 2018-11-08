<?php
################################################################################
#                                                                              #
# Webmoney Signer PHP edition by DKameleon (http://dkameleon.com)              #
#                                                                              #
# Updates and new versions: http://my-tools.net/wmxi/                          #
#                                                                              #
# Server requirements:                                                         #
# - BCMath or GMP                                                              #
# - MD4 or MHash or Hash                                                       #
#                                                                              #
################################################################################


# including MD4 class if exists
if (!defined('__DIR__')) { define('__DIR__', dirname(__FILE__)); }
if (file_exists(__DIR__ . DIRECTORY_SEPARATOR . 'MD4.php')) { include_once(__DIR__ . DIRECTORY_SEPARATOR . 'MD4.php'); }


# WMSigner class
class WMSigner {

	private $wmid = '';

	private $ekey = '';
	private $nkey = '';

	private $md4 = null;

	# debug switch
	private $debug = false;

	# constructor
	public function __construct($wmid, $key) {
		# MD4 checks
		if (!function_exists('mhash') && !function_exists('hash')) {
			if (class_exists('MD4')) {
				$this->md4 = new MD4(true);
			} else {
				throw new Exception('Supported MD4 implementations not found.');
			}
		}

		$this->wmid = $wmid;

		# loading e-n-key
		if (isset($key['ekey']) && isset($key['nkey'])) {
			$this->ekey = $key['ekey'];
			$this->nkey = $key['nkey'];
			return true;
		}

		$pass = isset($key['pass']) ? $key['pass'] : '';
		if (isset($key['file'])) {
			if (!file_exists($key['file'])) { throw new Exception('Key file not found: ' . $key['file']); }
			$data = file_get_contents($key['file']);
		}
		if (isset($key['data'])) { $data = $key['data']; }
		# seems can be another size (162 bytes)
#		if (strlen($data) != 164) { throw new Exception('Key data has invalid size: ' . strlen($data)); }

		// extracting n & e from data
		$key_data = unpack('vreserved/vsignflag/a16crc/Vlen/a*buf', $data);
		$key_test = $this->SecureKeyByIDPW($wmid, $pass, $key_data);
		$sign_keys = $this->Init($key_test);
		$this->ekey = $this->_hex2dec(bin2hex(strrev($sign_keys['ekey'])));
		$this->nkey = $this->_hex2dec(bin2hex(strrev($sign_keys['nkey'])));
	}


	# export keys for feature usage
	public function ExportKeys() {
		return array('ekey' => $this->ekey, 'nkey' => $this->nkey);
	}


	# md4 wrapper
	private function _md4($data) {
		if (function_exists('mhash')) { return mhash(MHASH_MD4, $data); }
		if (function_exists('hash')) { return hash('md4', $data, true); }
		if ($this->md4) { return $this->md4->Calc($data, true); }
		throw new Exception('MD4 implementations not found.');
	}


	# bcpowmod wrapper for old PHP
	private function _bcpowmod($m, $e, $n) {
		if (function_exists('bcpowmod')) { return bcpowmod($m, $e, $n); }
		if (function_exists('gmp_powm')) { return gmp_strval(gmp_powm($m, $e, $n)); }

		$r = '';
		while ($e != '0') {
			$t = bcmod($e, '4096');
			$r = substr('000000000000'.decbin(intval($t)), -12).$r;
			$e = bcdiv($e, '4096');
		}
		$r = preg_replace('!^0+!', '', $r);
		if ($r == '') $r = '0';
		$m = bcmod($m, $n);
		$erb = strrev($r);
		$result = '1';
		$a[0] = $m;
		for ($i = 1; $i < strlen($erb); $i++) {
			$a[$i] = bcmod(bcmul($a[$i-1], $a[$i-1]), $n);
		}
		for ($i = 0; $i < strlen($erb); $i++) {
			if ($erb[$i] == '1') {
				$result = bcmod(bcmul($result, $a[$i]), $n);
			}
		}
		return $result;
	}


	# XOR two strings
	private function _XOR($str, $xor_str, $shift = 0) {
		$str_len = strlen($str);
		$xor_len = strlen($xor_str);
		$i = $shift;
		$k = 0;
		while ($i < $str_len) {
			$str{$i} = chr(ord($str[$i]) ^ ord($xor_str[$k]));
			$i++;
			$k++;
			if ($k >= $xor_len) { $k = 0; }
		}
		return $str;
	}


	# convert decimal to hexadecimal
	private function _dec2hex($number) {
		if (function_exists('gmp_strval')) {
			$hexval = gmp_strval($number, 16);
			if (strlen($hexval) % 2) { $hexval = '0'.$hexval; }
			return $hexval;
		}

		$hexvalues = array('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F');
		$hexval = '';
		while($number != '0') {
			$hexval = $hexvalues[bcmod($number, '16')].$hexval;
			$number = bcdiv($number, '16', 0);
		}
		if (strlen($hexval) % 2) { $hexval = '0'.$hexval; }
		return $hexval;
	}


	# convert hexadecimal to decimal
	private function _hex2dec($number) {
		if (function_exists('gmp_strval')) { return gmp_strval("0x$number", 10); }

		$decvalues = array(
			'0' => '0', '1' => '1', '2' => '2', '3' => '3',
			'4' => '4', '5' => '5', '6' => '6', '7' => '7',
			'8' => '8', '9' => '9', 'A' => '10', 'B' => '11',
			'C' => '12', 'D' => '13', 'E' => '14', 'F' => '15');
		$decval = '0';
		$number = strrev(strtoupper($number));
		for($i = 0; $i < strlen($number); $i++) {
			$decval = bcadd(bcmul(bcpow('16', $i, 0), $decvalues[$number[$i]]), $decval);
		}
		return $decval;
	}


	# swap hexadecimal string
	private function _shortunswap($hex_str) {
		$result = '';
		while(strlen($hex_str) < 132) { $hex_str = '00'.$hex_str; }
		for($i = 0; $i < strlen($hex_str) / 4; $i++) {
			$result = substr($hex_str, $i * 4, 4).$result;
		}
		return $result;
	}


	# both of SecureKeyByIDPW
	private function SecureKeyByIDPW($wmid, $pass, $key_data) {
		$digest = $this->_md4($wmid . $pass);
		$result = $key_data;
		$result['buf'] = $this->_XOR($result['buf'], $digest, 6);
		return $result;
	}


	# initializing E and N
	private function Init($key_data) {
		$crc_cont = '';
		$crc_cont .= pack('v', $key_data['reserved']);
		$crc_cont .= pack('v', 0);
		$crc_cont .= pack('V4', 0, 0, 0, 0);
		$crc_cont .= pack('V', $key_data['len']);
		$crc_cont .= $key_data['buf'];
		$digest = $this->_md4($crc_cont);
		if (strcmp($digest, $key_data['crc'])) { throw new Exception('Checksum failed. KWM seems corrupted.'); }

		$keys = unpack('Vreserved/ve_len', $key_data['buf']);
		$keys = unpack('Vreserved/ve_len/a'.$keys['e_len'].'ekey/vn_len', $key_data['buf']);
		$keys = unpack('Vreserved/ve_len/a'.$keys['e_len'].'ekey/vn_len/a'.$keys['n_len'].'nkey', $key_data['buf']);
		return $keys;
	}


	# sign data
	public function Sign($data) {
		if ($this->ekey == '' || $this->nkey == '') { throw new Exception('Key is not loaded.'); }

		$result = '';
		$plain = $this->_md4($data);
		for($i = 0; $i < 10; ++$i) { $plain .= pack('V', $this->debug ? 0 : mt_rand()); }
		$plain = pack('v', strlen($plain)).$plain;
		$m = $this->_hex2dec(bin2hex(strrev($plain)));
		$a = $this->_bcpowmod($m, $this->ekey, $this->nkey);
		$result = strtolower($this->_shortunswap($this->_dec2hex($a)));
		return $result;
	}


}


?>
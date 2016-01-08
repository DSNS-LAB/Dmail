<?php

function addDnssecNote($address, $name, $source, $certtype, $method){
	$dnssec_note = "Created by DNSSEC.(POSO)Do not change this message.";
	$note_field = 'notes';
	$note_result = null;
	$name_field = 'name';
	$pgp_offset = 20;
	$smime_offset = 22;

	// Get someone's notes from address book
	$note_result = getAddressBookNotes($address);

	$matches = checkDnssecNote($note_result);
	if ($matches === null) {
		$note_result = $note_result . "\n" . $dnssec_note;
		$matches = checkDnssecNote($note_result);
	}

	// Give the keyword by the method of getting CERT
	switch ($certtype) {
		case 'PGP':
			switch ($method) {
				case 'delete':
					$note_result[$matches[0][1] + $pgp_offset] = 'O';
					break;
				case 'dnssec':
					$note_result[$matches[0][1] + $pgp_offset] = 'D';
					break;
				case 'import':
					$note_result[$matches[0][1] + $pgp_offset] = 'I';
					break;
			}
			break;
		case 'PKIX':
			switch ($method) {
				case 'delete':
					$note_result[$matches[0][1] + $smime_offset] = 'O';
					break;
				case 'dnssec':
					$note_result[$matches[0][1] + $smime_offset] = 'D';
					break;
				case 'import':
					$note_result[$matches[0][1] + $smime_offset] = 'I';
					break;
			}
			break;
	}

	// Get someone's name if $name is NULL
	$params = $GLOBALS['injector']->getInstance('IMP_Contacts')->getAddressbookSearchParams();
	if (is_null($name)) {
		try {
		$name = $GLOBALS['registry']->call('contacts/getField', array($address, $name_field, $params['sources'], true, false));
		} catch (Horde_Exception $e) {}
	}

//	$source = $GLOBALS['prefs']->getValue('add_source');
	try {
	$GLOBALS['registry']->call('contacts/addField', array($address, $name, $note_field, $note_result, $source));
	} catch (Horde_Exception $e) {}
}


function getAddressBookNotes($address){
	$note_field = 'notes';
	$note_result = null;

	// Get someone's notes from address book
	$params = $GLOBALS['injector']->getInstance('IMP_Contacts')->getAddressbookSearchParams();
	try {
	$note_result = $GLOBALS['registry']->call('contacts/getField', array($address, $note_field, $params['sources'], true, false));
	} catch (Horde_Exception $e) {}

	return $note_result;
}


function checkDnssecNote($note_result){
// Check keyword in notes table of address book
	$note_check = '#Created by DNSSEC\.\(P[DIO]S[DIO]\)Do not change this message\.#';
	$got = preg_match($note_check, $note_result, $matches, PREG_OFFSET_CAPTURE);

	if (!$got) {
//		echo "null array!";
		return null;
	}else return $matches;
}


function fixDnssecNoteStatus($source, $address, $name){
// Compare DNSSEC Notes and CERT status are match or not. If not, fix the DNSSEC note status.
	$status = array('PGP' => null, 'PKIX' => null);
	$dnssec_note = "Created by DNSSEC.(POSO)Do not change this message.";
	$pgp_offset = 20;
	$smime_offset = 22;
	$pgp_field='pgpPublicKey';
	$smime_field='smimePublicKey';
	$note_field = 'notes';

	// Get CERT status
	$note_result = getAddressBookNotes($address);
	$matches = checkDnssecNote($note_result);
	if ($matches === null) {
		$note_result = $note_result . "\n" . $dnssec_note;
		$matches = checkDnssecNote($note_result);
	}
	$status['PGP'] = $note_result[$matches[0][1] + $pgp_offset];
	$status['PKIX'] = $note_result[$matches[0][1] + $smime_offset];

	// Compare status and fix DNSSEC note status if needed.
	$params = $GLOBALS['injector']->getInstance('IMP_Contacts')->getAddressbookSearchParams();
	foreach ($status as $k => $v) {
		switch ($k) {
			case 'PGP':
				switch ($v) {
					case 'D':
					case 'I':
						$key_result = null;
						try {
						$key_result = $GLOBALS['registry']->call('contacts/getField', array($address, $pgp_field, $params['sources'], true, true));
						} catch (Horde_Exception $e) {}
						if (is_null($key_result)) {
							$status['PGP'] = 'O';
							$note_result[$matches[0][1] + $pgp_offset] = 'O';
						}
						break;
					case 'O':
						$key_result = null;
						try {
						$key_result = $GLOBALS['registry']->call('contacts/getField', array($address, $pgp_field, $params['sources'], true, true));
						} catch (Horde_Exception $e) {}
						if (!is_null($key_result)) {
							$status['PGP'] = 'I';
							$note_result[$matches[0][1] + $pgp_offset] = 'I';
						}
						break;
				}
				break;
			case 'PKIX':
				switch ($v) {
					case 'D':
					case 'I':
						$key_result = null;
						try {
						$key_result = $GLOBALS['registry']->call('contacts/getField', array($address, $smime_field, $params['sources'], true, true));
						} catch (Horde_Exception $e) {}
						if (is_null($key_result)) {
							$status['PKIX'] = 'O';
							$note_result[$matches[0][1] + $smime_offset] = 'O';
						}
						break;
					case 'O':
						$key_result = null;
						try {
						$key_result = $GLOBALS['registry']->call('contacts/getField', array($address, $smime_field, $params['sources'], true, true));
						} catch (Horde_Exception $e) {}
						if (!is_null($key_result)) {
							$status['PKIX'] = 'I';
							$note_result[$matches[0][1] + $smime_offset] = 'I';
						}
						break;
				}
				break;
		}
	}
	try {
	$GLOBALS['registry']->call('contacts/addField', array($address, $name, $note_field, $note_result, $source));
	} catch (Horde_Exception $e) {}

	return $status;
}


function resumePgpCrc($pgp_raw_key){
// resume the CRC code of PGP public cert which is deleted because of BASE64 format for DNS CERT type
	if ( $pgp_raw_key[strlen($pgp_raw_key)-1] != "=" ) {
		$pgp_raw_key = $pgp_raw_key . "=";
	}

	$public_key = "-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.11 (GNU/Linux)

".$pgp_raw_key."
-----END PGP PUBLIC KEY BLOCK-----";

	$tmpFileName1 = tempnam(sys_get_temp_dir(),"dmail");
	$tmpFileName2 = tempnam(sys_get_temp_dir(),"dmail");

	$tmpFileHandle = fopen($tmpFileName1,"w");
	fwrite($tmpFileHandle,$public_key);
	fclose($tmpFileHandle);

	// Transfer ASCII armor to Binary
	$cmd1 = "gpg --yes --output $tmpFileName2 --dearmor $tmpFileName1";
	// Transfer Binary to ASCII armor, then CRC code is resumeed
	$cmd2 = "gpg --yes --output $tmpFileName1 --enarmor $tmpFileName2";
	exec($cmd1);
	exec($cmd2);

	$tmpFileHandle = fopen($tmpFileName1,"r");
	$public_key = fread($tmpFileHandle, filesize($tmpFileName1));
	fclose($tmpFileHandle);

	unlink($tmpFileName2);
	unlink($tmpFileName1);

	if ($public_key[strlen($public_key)-1] != "\n")
	{
		$public_key .= "\n";
	}
	// convert $public_key to an array
	$KeyArray = explode("\n", $public_key, -1);
//	print_r($KeyArray);

	// remove the first 4 lines & last 1 lines , only leave the KEY BLOCK + CRC
	array_shift($KeyArray);
	array_shift($KeyArray);
	array_shift($KeyArray);
	array_shift($KeyArray);
	array_pop($KeyArray);

	$pgp_raw_key = implode("\n", $KeyArray);
//	echo $pgp_raw_key;

	return $pgp_raw_key;
}


function autoAddOrUpdateCert($address){
// auto add or update CERT to address book when send encrypt e-mail or verify sign e-mail
	// check the e-mail address is not the ID owner's e-mail
	$checkowner = $GLOBALS['injector']->getInstance('IMP_Identity');
	if (!$checkowner->hasAddress($address))
	{
		$source=$GLOBALS['prefs']->getValue('add_source');
		$name=explode('@',$address);
		getDnssecCert($source,$address,$name[0]);
        }
}


function getDnssecCert($source,$email,$name){ 
//get CERT from DNSSEC and put it in contacts
//	require "dmailconf.php";
	$DNSSEC_SRV="127.0.0.1";
//	$DNSSEC_SRV=$dconf['resolver'];
	$pgp_field='pgpPublicKey';
	$smime_field='smimePublicKey';
	$DomainEmail=preg_replace("/@/",".",$email);
	$status = null;

	$cmd="dig +noall +answer +tcp -t cert $DomainEmail @$DNSSEC_SRV";
	exec($cmd,$cmd_ret);
//	var_dump($cmd_ret);

	// Fix and get DNSSEC note status
	$status = fixDnssecNoteStatus($source,$email,$name);

	// Delete original CERT
//	try {
//	$GLOBALS['registry']->call('contacts/deleteField',array($email,$pgp_field,array($source)));
//	$GLOBALS['registry']->call('contacts/deleteField',array($email,$smime_field,array($source)));
//	}
//	catch(Exception $e){
//	}

	// Delete original CERT if CERT status is 'D'
	if ($status['PGP'] == 'D') {
		try {
		$GLOBALS['registry']->call('contacts/deleteField',array($email,$pgp_field,array($source)));
		} catch(Exception $e){}
		$status['PGP'] = 'O';
		addDnssecNote($email, $name, $source, 'PGP', 'delete');
	}
	if ($status['PKIX'] == 'D') {
		try {
		$GLOBALS['registry']->call('contacts/deleteField',array($email,$smime_field,array($source)));
		} catch(Exception $e){}
		$status['PKIX'] = 'O';
		addDnssecNote($email, $name, $source, 'PKIX', 'delete');
	}

	if ( count($cmd_ret)==0 ) { // No CERT is found
		return;
	}

	for ($i=0; $i<2; $i++) {
		if ( count($cmd_ret[$i])==0 ) {
			break;
		}

		$cmd_ret_arr[$i]=preg_split("#[\s]+#",$cmd_ret[$i],8);
//		var_dump($cmd_ret_arr);
		$certtype=$cmd_ret_arr[$i][4];
//		var_dump($certtype);
		switch ($certtype) {
			case "PGP":
				$raw_key = resumePgpCrc($cmd_ret_arr[$i][7]);
				break;
			case "PKIX":
				$raw_key = str_replace(" ","\n",$cmd_ret_arr[$i][7]);
				break;
		}
//		var_dump($raw_key);

		switch ($certtype) {
			case "PGP":
				$public_key="-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.11 (GNU/Linux)

".$raw_key."
-----END PGP PUBLIC KEY BLOCK-----";
//				var_dump($public_key);
				if ($status['PGP'] == 'I') {
					try {
					$GLOBALS['registry']->call('contacts/deleteField',array($email,$pgp_field,array($source)));
					} catch(Exception $e){}
				}
				try {
				$GLOBALS['registry']->call('contacts/addField', array($email, $name, $pgp_field, $public_key, $source)); 
				} catch(Exception $e){}
				addDnssecNote($email, $name, $source, 'PGP', 'dnssec');
				break;
			case "PKIX":
				$public_key="-----BEGIN CERTIFICATE-----
".$raw_key."
-----END CERTIFICATE-----";
//				var_dump($public_key);
				if ($status['PKIX'] == 'I') {
					try {
					$GLOBALS['registry']->call('contacts/deleteField',array($email,$smime_field,array($source)));
					} catch(Exception $e){}
				}
				try {
				$GLOBALS['registry']->call('contacts/addField', array($email, $name, $smime_field, $public_key, $source)); 
				} catch(Exception $e){}
				addDnssecNote($email, $name, $source, 'PKIX', 'dnssec');
				break;
		}
	}
//	var_dump($cmd_ret_arr);
}


function forceCertEmailInfo(){
// To force E-mail infomation of CERT be (User's login ID)@(Domain of Login IMAP server)
// And to force Name infomation of CERT be (User's login ID)
// For reference: imp/lib/Prefs/Identity.php function getFromAddress()
	$email = $GLOBALS['registry']->getAuth();

	if (!strstr($email, '@')) {
		$email .= '@' . $GLOBALS['injector']->getInstance('IMP_Factory_Imap')->create()->config->maildomain;
	}

	$emailob = new Horde_Mail_Rfc822_Address($email);

	if (is_null($emailob->personal)) {
		$emailob->personal = $GLOBALS['injector']->getInstance('IMP_Identity')->getFullname();
	}
	
	$email_array['address'] = $emailob->bare_address;
	$email_temp = explode("@", $emailob->bare_address, -1);
	$email_array['id'] = $email_temp[0];
	
	return $email_array;
}


function getDomainEmail($KeyString,$certtype){
// Get user's e-mail from CERT
	switch ($certtype) {
		case "PGP":
			// Get user's e-mail from PGP Cert information
//			global $injector;
//			$pgpObject=$injector->getInstance('IMP_Crypt_Pgp');
//			$KeyInfo=$pgpObject->pgpPrettyKey($KeyString);
			$KeyInfo=$GLOBALS['injector']->getInstance('IMP_Crypt_Pgp')->pgpPrettyKey($KeyString);
	
//			echo $KeyInfo;
			$tmp1=explode("\n",$KeyInfo,8);
			$tmp2=explode(" ",$tmp1[6],2);
			$email=$tmp2[1];
			break;
		case "PKIX":
			// Get user's e-mail from SMIME Cert
			$email=$GLOBALS['injector']->getInstance('IMP_Crypt_Smime')->getEmailFromKey($KeyString);
			break;
	}

	$DomainEmail=preg_replace("/@/",".",$email);
	$DomainEmail=str_replace(" ","",$DomainEmail);
//	echo "$DomainEmail \n";
//	$a=strlen($DomainEmail);
//	echo $a;

	return $DomainEmail;
}


function getKeyBlock($KeyString,$certtype){
//	echo $KeyString;
	// if the last word of $KeyString is not \n, add \n to the last potision of $KeyString.
	if ($KeyString[strlen($KeyString)-1] != "\n")
	{
		$KeyString .= "\n";
	}
	// convert $KeyString to an array
	$KeyArray = explode("\n", $KeyString, -1);
//	print_r($KeyArray);

	// Get the KEY BLOCK
	switch ($certtype) {
		case "PGP":
			// remove the first 3 lines & last 2 lines , only leave the KEY BLOCK
			array_shift($KeyArray);
			array_shift($KeyArray);
			array_shift($KeyArray);
			array_pop($KeyArray);
			array_pop($KeyArray); // CRC part is not support in DNS, must remove it to make KEY BLOCK as BASE64
			break;
		case "PKIX":
			// remove the first 6 lines & last 1 line , only leave the KEY BLOCK
			array_shift($KeyArray);
			array_shift($KeyArray);
			array_shift($KeyArray);
			array_shift($KeyArray);
			array_shift($KeyArray);
			array_shift($KeyArray);
			array_pop($KeyArray);
			break;
	}

	$key=implode($KeyArray);
	$key=str_replace("\n","",$key);
	$key=str_replace("\r","",$key);
//	echo $key;

	return $key;
}


function addDnssecCert($KeyString,$certtype){
// add a CERT RR into the DNSSEC server
	require "dmailconf.php";
//	$TTL="300";
	$TTL=$dconf['nsupdate']['ttl'];
//	$DNS_NS="ns.site1.org";
	$DNS_NS=$dconf['nsupdate']['nameserver'];
//	$TSIGkey="/var/www/horde/dnssec/webmail-key.key";
	$TSIGkey=$dconf['nsupdate']['tsigkey'];

	$DomainEmail=getDomainEmail($KeyString,$certtype);
	$key=getKeyBlock($KeyString,$certtype);

	$tmpFileName=tempnam(sys_get_temp_dir(),"dmail");
	$tmpFileHandle=fopen($tmpFileName,"w");

	// nsupdate cmd for localhost dnssec authoritative server, and add the prescribed CERT RR
//	$context="update add $DomainEmail $TTL IN CERT $certtype 0 0 $key\nsend\n";
	// nsupdate cmd for remote dnssec authoritative server, and add the prescribed CERT RR
//	$context="server $DNS_NS\nupdate add $DomainEmail $TTL IN CERT $certtype 0 0 $key\nsend\n";
	// nsupdate cmd for remote dnssec authoritative server, and delete ALL CERT RR (PGP & PKIX), then add the prescribed CERT RR
	$context="server $DNS_NS\nupdate delete $DomainEmail CERT\nupdate add $DomainEmail $TTL IN CERT $certtype 0 0 $key\nsend\n";
//	echo $context;

	fwrite($tmpFileHandle,$context);
	fclose($tmpFileHandle);

	// nsupdate cmd for localhost dnssec authoritative server
//	$cmd="nsupdate -l $tmpFileName";
	// nsupdate cmd for remote dnssec authoritative server
	$cmd="nsupdate -k $TSIGkey $tmpFileName";
//	echo $cmd;

	exec($cmd,$cmd_ret);
//	$a=implode($cmd_ret);
//	echo $a;

	unlink($tmpFileName);
}


function delDnssecCert($certtype){
// remove the CERT RR from the DNSSEC server
	require "dmailconf.php";
//	$DNS_NS="ns.site1.org";
	$DNS_NS=$dconf['nsupdate']['nameserver'];
//	$TSIGkey="/var/www/horde/dnssec/webmail-key.key";
	$TSIGkey=$dconf['nsupdate']['tsigkey'];

	switch ($certtype) {
		case "PGP":
			$PubKey=$GLOBALS['prefs']->getValue('pgp_public_key');
			break;
		case "PKIX":
			$PubKey=$GLOBALS['prefs']->getValue('smime_public_key');
			break;
	}

	$DomainEmail=getDomainEmail($PubKey,$certtype);
	$key=getKeyBlock($PubKey,$certtype);
//	$DNSSEC_SRV="localhost";
//	$cmd="dig +noall +answer +tcp -t cert $DomainEmail @$DNSSEC_SRV";
//	exec($cmd,$cmd_ret);

	$tmpFileName=tempnam(sys_get_temp_dir(),"dmail");
	$tmpFileHandle=fopen($tmpFileName,"w");

	// nsupdate cmd for localhost dnssec authoritative server, and delete the prescribed CERT RR
//	$context="update delete $DomainEmail CERT $certtype 0 0 $key\nsend\n";
	// nsupdate cmd for remote dnssec authoritative server, and delete the prescribed CERT RR
//	$context="server $DNS_NS\nupdate delete $DomainEmail CERT $certtype 0 0 $key\nsend\n";
	// nsupdate cmd for remote dnssec authoritative server, and delete ALL CERT RR (PGP & PKIX)
	$context="server $DNS_NS\nupdate delete $DomainEmail CERT\nsend\n";
//	echo $context;

	fwrite($tmpFileHandle,$context);
	fclose($tmpFileHandle);

	// nsupdate cmd for localhost dnssec authoritative server
//	$cmd="nsupdate -l $tmpFileName";
	// nsupdate cmd for remote dnssec authoritative server
	$cmd="nsupdate -k $TSIGkey $tmpFileName";
	exec($cmd,$cmd_ret);

//	$a=implode($cmd_ret);
//	echo $a;
	unlink($tmpFileName);
}

/*
$public_key="-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1.4.11 (GNU/Linux)

mQGiBFBMmJMRBADoreNIZKIiApD5us1Xi3E6yGi/vBxPkX9apK1H9KdeaTjm7nYH
N+kqbsQl6QiOpg3yaZNI5+HH59hOedB/SOt7bmDf8wsMTRE6EbvnmZ3KWp+Ipmeu
jbtZmxO250XhzhScbi6RmDleiCAsCBW0q1Us/YxiuGLrJtZxYH4lYr/jOwCg35WH
UFxOpofDUsCs+0sDhZN7oSkEAMfmC/wfXxXY524/v2y6JQTlw0U1/tm+iEBZXDmh
IxgkxhKQYEFd3N32p7UwOwCEsOuvHfxZJrU94TekUbqc5Hb6TnbkB2I/klAQ7J6z
S2voUAdsxYW+9QciVkq2nE8ctlGVr+65qhcDN6xYrnvZr3Vwcwqgfe7/Dy8o/ADX
8vbpBACAfUMtGRPwt3qikhMAqEqN8Ilg4MERxw9GcRAfVYkti/+B2mid/TnyXjpW
PGpFDWfFS1rANT144h83HX8RJ1xHElBc2rIlEFwlHXXIw+P2iPv6jr189bGZXeee
5gHfclZQBpT/Zp3lL2g0yLEH+67M/WonNX+TPH2U/kTtBfHAO7QXcDMgPHAzQHVi
dDEyLjA0c3J2Lm5ldD6IYgQTEQIAIgUCUEyYkwIbIwYLCQgHAwIGFQgCCQoLBBYC
AwECHgECF4AACgkQq/gFZIy1V6F6XgCghjYdkKzYrMQe2/ISTkG7sVn/urwAoJsx
d9fC9Xlga6LOEG39/v7M96XmuQENBFBMmJMQBAChvlPXY2fQB2mF/e/RjVPpyhNx
7akPgFPPJ/x8Akcdjm3rWXoMc2SylBgl79Hlt9cCSoavWB6VdB7/NaBUOZHy2BPS
HViG3aUEaV7V73VCj/HkXK8mEX8xw358PcEk3rOlaJWSWGBkb1O5td9SvXySJeMR
gPTsZVFkJPZqIF1J/wADBQP+M3MkcbOAqdUy7SNBcxJ3SzCQEZs9pMSoitt763BB
1tJuD+Ncx1OSc53UhnFxbeOJT+dQBJxqK1AzZCKennYE+YArfilgqF3WnVOVI3Vw
sKCmFHS4eot0bJXc6cUAwr8vAtTB31oo2Ev041tHsFMGqtS0ZxITwT5eKx4aP2Rd
FVyISQQYEQIACQUCUEyYkwIbDAAKCRCr+AVkjLVXoYVVAJ9dt2U1jMGha9Mkk1ro
nUp29WBKQACePP9IfIHZ+I72leWu9HxzgBpBsQ4=
=tcK6
-----END PGP PUBLIC KEY BLOCK-----";
*/

?>

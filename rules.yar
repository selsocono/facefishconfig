rule FaceFish_UPX_overlay_trick {
	strings:
		$sig = {00 00 00 00 55 50 58 21 00 00 00 00 00 00 55 50 58 21}
   condition:
       uint32be ( 0 ) == 0x7F454C46 and all of ( $sig* ) and for any i in ( 150 .. 180 ) : ( uint8be ( @sig + i ) )
}

rule FaceFish_Config {
	strings:
		$a1 = {00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 84 80 84 80 84 80 84 80 88 80 88 80 88 80 88}
	condition:
		uint32be ( 0 ) == 0x7F454C46 and all of them
}

rule FaceFish_Rootkit{
	strings:
		$export_init = "sshinit" ascii
		$export_bind = "bind" ascii
		$remoteShellCmd = "/bin/sh" ascii
		$remoteShellOpt = "-i" ascii
		$interceptedFunc1 = "sshpam_auth_passwd" ascii
		$interceptedFunc2 = "auth_shadow_pwexpired" ascii
		$interceptedFunc3 = "getpwnamallow" ascii
		$interceptedFunc4 = "do_log" ascii
		$interceptedFunc5 = "login_write" ascii
		$interceptedFunc6 = "read_passphrase" ascii
		$interceptedFunc7 = "ssh_userauth2" ascii
		$interceptedFunc8 = "key_perm_ok" ascii
		$interceptedFunc9 = "load_identity_file" ascii
		$loadCommandCode1 = {BF 00 03 00 00}
		$loadCommandCode2 = {BF 01 03 00 00}
		$loadCommandCode3 = {BF 05 03 00 00}
		$loadCommandCode4 = {BF 11 03 00 00}
	condition:
		uint32be ( 0 ) == 0x7F454C46 and filesize < 300000 and ( all of ( $export* ) ) and ( all of ( $remoteShel* ) ) and ( any of ( $interceptedFunc* ) ) and ( 2 of ( $loadCommandCode* ) )
}
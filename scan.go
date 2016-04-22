package main

func scanWp(version string) VulnRes {
	return VulnRes{OK:false}
}

func scanPlugin(slug, version string) VulnRes {
	return VulnRes{OK:true}
}

func scanTheme(slug, version string) VulnRes {
	return VulnRes{OK:true}
}


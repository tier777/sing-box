package daemon

import "testing"

func TestLocalProfileFilesystemConfinement(t *testing.T) {
	valid := []string{
		`{}`, `{ "experimental":{"cache_file":{"enabled":true}} }`,
		`{ "outbounds":[{"type":"direct","tag":"DIRECT"}],"endpoints":[{"type":"tailscale","tag":"YOUTUBE","state_directory":"tailscale-router"}] }`,
	}
	for _, profile := range valid {
		if err := ValidateLocalProfile(profile); err != nil {
			t.Errorf("valid profile rejected: %v", err)
		}
	}
	invalid := []string{
		`{"ntp":{"enabled":true,"write_to_system":true,"server":"invalid.test"}}`,
		`{"log":{"output":"/etc/root-owned"}}`,
		`{"experimental":{"clash_api":{"external_ui":"/etc"}}}`,
		`{"experimental":{"debug":{}}}`,
		`{"experimental":{"v2ray_api":{"listen":"0.0.0.0:8080"}}}`,
		`{"experimental":{"cache_file":"/etc/root-owned"}}`,
		`{"experimental":{"cache_file":{"enabled":true,"path":"/etc/root-owned"}}}`,
		`{"endpoints":[{"type":"tailscale","taildrop_directory":"/etc"}]}`,
		`{"certificate_providers":[{"data_directory":"/etc"}]}`,
		`{"services":[{"type":"derp"}]}`,
		`{"endpoints":[{"type":"tailscale","state_directory":"$HOME/foo"}]}`,
		`{"endpoints":[{"type":"tailscale","state_directory":"../foo"}]}`,
		`{"endpoints":[{"type":"tailscale","state_directory":"a/b"}]}`,
		`{"endpoints":[{"type":"tailscale","state_directory":"/etc"}]}`,
		`{"endpoints":[{"type":"tailscale","ssh_server":true}]}`,
		`{"endpoints":[{"type":"openconnect","client_key_path":"/etc/key"}]}`,
		`{"inbounds":[{"type":"mixed"}]}`,
		`{"outbounds":[{"type":"tor"}]}`,
		`{"network_namespaces":[{"type":"managed"}]}`,
	}
	for _, profile := range invalid {
		if ValidateLocalProfile(profile) == nil {
			t.Errorf("unsafe profile accepted: %s", profile)
		}
	}
}

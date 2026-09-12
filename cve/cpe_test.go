package cve

import "testing"

func TestCPEWithVersion(t *testing.T) {
	tests := []struct {
		name, cpe, version, want string
		wantErr                  bool
	}{
		{
			name:    "nginx",
			cpe:     "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
			version: "1.18.0",
			want:    "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*",
		},
		{
			name:    "escapes reserved characters",
			cpe:     "cpe:2.3:a:x:y:*:*:*:*:*:*:*:*",
			version: "1.0+rc1:a",
			want:    `cpe:2.3:a:x:y:1.0\+rc1\:a:*:*:*:*:*:*:*`,
		},
		{
			name:    "keeps escaped colon in vendor",
			cpe:     `cpe:2.3:a:ex\:ample:y:*:*:*:*:*:*:*:*`,
			version: "2.0",
			want:    `cpe:2.3:a:ex\:ample:y:2.0:*:*:*:*:*:*:*`,
		},
		{name: "too few fields", cpe: "cpe:2.3:a:x:y", version: "1", wantErr: true},
		{name: "cpe 2.2 uri", cpe: "cpe:/a:x:y:1:::::::", version: "1", wantErr: true},
		{name: "empty", cpe: "", version: "1", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CPEWithVersion(tt.cpe, tt.version)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

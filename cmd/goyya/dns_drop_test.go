package main

import "testing"

func TestBuildAdServersDB(t *testing.T) {
	db := buildAdServerDb("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts")

	if db == nil {
		t.Error("error building Adserver")
	}

	t.Logf("%+v", db)
}

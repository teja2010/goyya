package main

import "testing"

func TestBuildAdServersDB(t *testing.T) {
	db := buildAdServerDb("https://easylist.to/easylist/easylist.txt")

	if db == nil {
		t.Error("error building Adserver")
	}

	t.Logf("%+v", db)
}

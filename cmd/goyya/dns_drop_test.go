package main

import "testing"

func TestBuildAdServersDB(t *testing.T) {
	db := buildAdServerDb("https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/EnglishFilter/sections/adservers.txt")

	if db == nil {
		t.Error("error building Adserver")
	}

	t.Logf("%+v", db)
}
